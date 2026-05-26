// =====================================================
// LinkUp - フロントエンド アプリケーション
// Firebase Realtime Database 版（通話以外のすべての通信に使用）
// =====================================================

// =====================================================
// 暗号化ユーティリティ
// =====================================================
class CryptoUtil {
    static async generateKey() {
        return await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    static async exportKey(key) {
        const exported = await window.crypto.subtle.exportKey("raw", key);
        return Array.from(new Uint8Array(exported))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    static async importKey(keyData) {
        const keyBytes = new Uint8Array(keyData.match(/.{2}/g).map(b => parseInt(b, 16)));
        return await window.crypto.subtle.importKey("raw", keyBytes, "AES-GCM", true, ["encrypt", "decrypt"]);
    }

    static async encrypt(key, data) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
        return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
    }

    static async decrypt(key, iv, encryptedData) {
        return await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: new Uint8Array(iv) },
            key,
            new Uint8Array(encryptedData)
        );
    }

    // パスワード用シンプルハッシュ（GAS版と同じアルゴリズム）
    static simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        const salted = 'svc_' + str + '_hash';
        let hash2 = 0;
        for (let i = 0; i < salted.length; i++) {
            const char = salted.charCodeAt(i);
            hash2 = ((hash2 << 5) - hash2) + char;
            hash2 = hash2 & hash2;
        }
        return Math.abs(hash).toString(16) + Math.abs(hash2).toString(16);
    }

    static generateToken() {
        // UUID v4 風の十分にランダムなトークン
        const a = crypto.getRandomValues(new Uint8Array(16));
        return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('')
            + '-' + Date.now().toString(36);
    }
}

// =====================================================
// Firebase API クライアント
// =====================================================
// Realtime Database を直接操作する、旧 GasAPI と同等の機能を提供するラッパー
class FbAPI {
    static _db = null;          // firebase.database()
    static _signalsRef = null;  // 自分宛シグナルの subscribe ref
    static _signalsHandler = null;
    static _heartbeatTimeout = 12 * 1000;  // 12秒（旧GAS版と同じ）
    static _signalTimeout = 5 * 60 * 1000; // 5分

    static init() {
        if (!window.firebase) throw new Error('Firebase SDKが読み込まれていません');
        if (!window.FIREBASE_CONFIG) throw new Error('firebase-config.js の設定がありません');
        if (!firebase.apps.length) {
            firebase.initializeApp(window.FIREBASE_CONFIG);
        }
        this._db = firebase.database();
        console.log('[Firebase] 初期化完了');
    }

    static _now() { return Date.now(); }
    static _isoNow() { return new Date().toISOString(); }

    // ----------------- アカウント登録 -----------------
    static async register(name, password) {
        name = (name || '').trim();
        password = (password || '').trim();
        if (!name || name.length < 1 || name.length > 20) return { ok: false, error: '名前は1〜20文字で入力してください' };
        if (!password || password.length < 4) return { ok: false, error: 'パスワードは英数字4文字以上で入力してください' };
        if (!/^[a-zA-Z0-9]+$/.test(password)) return { ok: false, error: 'パスワードは半角英数字のみ使用できます' };

        const accRef = this._db.ref('accounts/' + this._encName(name));
        const snap = await accRef.get();
        if (snap.exists()) return { ok: false, error: 'この名前はすでに使用されています' };

        await accRef.set({
            name: name,
            passwordHash: CryptoUtil.simpleHash(password),
            createdAt: this._isoNow()
        });
        return { ok: true, message: '登録が完了しました' };
    }

    // ----------------- ログイン -----------------
    static async login(name, password, peerId) {
        name = (name || '').trim();
        password = (password || '').trim();
        peerId = (peerId || '').trim();
        if (!name || !password) return { ok: false, error: '名前とパスワードを入力してください' };

        const accSnap = await this._db.ref('accounts/' + this._encName(name)).get();
        if (!accSnap.exists()) return { ok: false, error: '名前またはパスワードが違います' };
        const acc = accSnap.val();
        if (acc.passwordHash !== CryptoUtil.simpleHash(password)) return { ok: false, error: '名前またはパスワードが違います' };

        // 既存セッションを削除
        await this._removeSessionsByName(name);

        const token = CryptoUtil.generateToken();
        await this._db.ref('sessions/' + token).set({
            name: name,
            peerId: peerId,
            lastBeat: this._now()
        });
        await this._db.ref('presence/' + this._encName(name)).set({
            peerId: peerId,
            lastBeat: this._now(),
            token: token
        });
        return { ok: true, token, name };
    }

    // ----------------- ログアウト -----------------
    static async logout(token) {
        if (!token) return { ok: false };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (sesSnap.exists()) {
            const name = sesSnap.val().name;
            await this._db.ref('sessions/' + token).remove();
            await this._db.ref('presence/' + this._encName(name)).remove();
        }
        return { ok: true };
    }

    // ----------------- ハートビート -----------------
    static async heartbeat(token, peerId) {
        if (!token) return { ok: false, error: 'トークンが必要です' };
        const sesRef = this._db.ref('sessions/' + token);
        const sesSnap = await sesRef.get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const ses = sesSnap.val();
        const updates = { lastBeat: this._now() };
        if (peerId) updates.peerId = peerId;
        await sesRef.update(updates);
        // presence も更新
        const presRef = this._db.ref('presence/' + this._encName(ses.name));
        const presUpdates = { lastBeat: this._now(), token: token };
        if (peerId) presUpdates.peerId = peerId;
        await presRef.update(presUpdates);
        return { ok: true, name: ses.name };
    }

    // ----------------- 全登録ユーザー一覧（管理者用） -----------------
    static async getAllAccounts(token) {
        if (!token) return { ok: false, error: 'トークンが必要です' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const accSnap = await this._db.ref('accounts').get();
        const names = [];
        if (accSnap.exists()) {
            const all = accSnap.val();
            for (const encName in all) {
                const a = all[encName];
                if (a && a.name) names.push(a.name);
            }
        }
        return { ok: true, names };
    }

    // ----------------- オンラインユーザーリスト -----------------
    static async onlineList(token) {
        if (!token) return { ok: false, error: 'トークンが必要です' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const presSnap = await this._db.ref('presence').get();
        const users = [];
        const now = this._now();
        if (presSnap.exists()) {
            const all = presSnap.val();
            for (const encName in all) {
                const p = all[encName];
                if (!p || !p.lastBeat) continue;
                const name = this._decName(encName);
                if (name === myName) continue;
                if ((now - p.lastBeat) < this._heartbeatTimeout) {
                    users.push({ name: name, peer_id: p.peerId || '' });
                }
            }
        }
        return { ok: true, users, my_name: myName };
    }

    // ----------------- シグナル送信 -----------------
    static async sendSignal(token, to, type, signalData) {
        if (!token || !to || !type) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const fromName = sesSnap.val().name;

        const sigRef = this._db.ref('signals/' + this._encName(to)).push();
        await sigRef.set({
            from: fromName,
            type: type,
            signal_data: signalData || '',
            timestamp: this._now()
        });
        return { ok: true, signal_id: sigRef.key };
    }

    // ----------------- シグナル既読化（削除） -----------------
    static async ackSignal(token, signalId, myName) {
        if (!token || !signalId) return { ok: false };
        // 自分の name は subscribe 時にキャッシュされている前提
        if (!myName) {
            const sesSnap = await this._db.ref('sessions/' + token).get();
            if (!sesSnap.exists()) return { ok: false };
            myName = sesSnap.val().name;
        }
        await this._db.ref('signals/' + this._encName(myName) + '/' + signalId).remove();
        return { ok: true };
    }

    // ----------------- シグナル受信のサブスクライブ -----------------
    // ポーリングの代わりにリアルタイムリスナーを使う
    // callback(signal) が新着シグナルごとに呼ばれる
    static subscribeSignals(myName, callback) {
        this.unsubscribeSignals();
        const ref = this._db.ref('signals/' + this._encName(myName));
        this._signalsRef = ref;
        this._signalsHandler = ref.on('child_added', snap => {
            const data = snap.val();
            if (!data) return;
            // 期限切れシグナルは無視
            if (data.timestamp && (this._now() - data.timestamp) >= this._signalTimeout) return;
            callback({
                id: snap.key,
                from: data.from,
                type: data.type,
                signal_data: data.signal_data || '',
                timestamp: data.timestamp
            });
        });
    }

    static unsubscribeSignals() {
        if (this._signalsRef && this._signalsHandler) {
            this._signalsRef.off('child_added', this._signalsHandler);
            this._signalsRef = null;
            this._signalsHandler = null;
        }
    }

    // friends ノード全体をリアルタイム購読する
    // コールバックには { friends, incoming, outgoing } を myName 基準で計算して渡す
    static subscribeFriends(getMyName, callback) {
        this.unsubscribeFriends();
        const ref = this._db.ref('friends');
        this._friendsRef = ref;
        this._friendsHandler = ref.on('value', snap => {
            const all = snap.val() || {};
            const myName = typeof getMyName === 'function' ? getMyName() : getMyName;
            if (!myName) return;
            const friends = [];
            const incoming = [];
            const outgoing = [];
            for (const k in all) {
                const v = all[k];
                if (!v) continue;
                if (v.status === 'accepted') {
                    if (v.from === myName) friends.push(v.to);
                    else if (v.to === myName) friends.push(v.from);
                } else if (v.status === 'pending') {
                    if (v.to === myName) incoming.push({ from: v.from });
                    else if (v.from === myName) outgoing.push({ to: v.to });
                }
            }
            try { callback({ ok: true, friends, incoming, outgoing }); } catch (_) { }
        });
    }

    static unsubscribeFriends() {
        if (this._friendsRef && this._friendsHandler) {
            this._friendsRef.off('value', this._friendsHandler);
            this._friendsRef = null;
            this._friendsHandler = null;
        }
    }

    // ----------------- フレンド申請 -----------------
    static async sendFriendRequest(token, to) {
        if (!token || !to) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const fromName = sesSnap.val().name;
        if (fromName === to) return { ok: false, error: '自分自身には申請できません' };
        if (!(await this._accountExists(to))) return { ok: false, error: 'ユーザーが見つかりません' };

        const key = this._friendKey(fromName, to);
        const ref = this._db.ref('friends/' + key);
        const snap = await ref.get();
        if (snap.exists()) {
            const v = snap.val();
            if (v.status === 'accepted') return { ok: false, error: 'すでにフレンドです' };
            if (v.status === 'pending') return { ok: false, error: 'すでに申請中です' };
        }
        await ref.set({
            from: fromName,
            to: to,
            status: 'pending',
            createdAt: this._isoNow()
        });
        return { ok: true };
    }

    static async acceptFriend(token, from) {
        if (!token || !from) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const key = this._friendKey(from, myName);
        const ref = this._db.ref('friends/' + key);
        const snap = await ref.get();
        if (!snap.exists() || snap.val().status !== 'pending' || snap.val().from !== from || snap.val().to !== myName) {
            return { ok: false, error: '申請が見つかりません' };
        }
        await ref.update({ status: 'accepted' });
        return { ok: true };
    }

    static async rejectFriend(token, from) {
        if (!token || !from) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const key = this._friendKey(from, myName);
        const ref = this._db.ref('friends/' + key);
        const snap = await ref.get();
        if (!snap.exists() || snap.val().status !== 'pending') {
            return { ok: false, error: '申請が見つかりません' };
        }
        await ref.remove();
        return { ok: true };
    }

    static async removeFriend(token, target) {
        if (!token || !target) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const key = this._friendKey(myName, target);
        const ref = this._db.ref('friends/' + key);
        const snap = await ref.get();
        if (!snap.exists()) return { ok: false, error: 'フレンドが見つかりません' };
        await ref.remove();
        return { ok: true };
    }

    static async getFriends(token) {
        if (!token) return { ok: false, error: 'トークンが必要です' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const allSnap = await this._db.ref('friends').get();
        const friends = [];
        const incoming = [];
        const outgoing = [];
        if (allSnap.exists()) {
            const all = allSnap.val();
            for (const k in all) {
                const v = all[k];
                if (!v) continue;
                if (v.status === 'accepted') {
                    if (v.from === myName) friends.push(v.to);
                    else if (v.to === myName) friends.push(v.from);
                } else if (v.status === 'pending') {
                    if (v.to === myName) incoming.push({ from: v.from });
                    else if (v.from === myName) outgoing.push({ to: v.to });
                }
            }
        }
        return { ok: true, friends, incoming, outgoing };
    }

    // ----------------- 名前変更 -----------------
    static async changeName(token, newName, password) {
        newName = (newName || '').trim();
        password = (password || '').trim();
        if (!token || !newName || !password) return { ok: false, error: 'パラメータが不足しています' };
        if (newName.length < 1 || newName.length > 20) return { ok: false, error: '名前は1〜20文字で入力してください' };

        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const accSnap = await this._db.ref('accounts/' + this._encName(myName)).get();
        if (!accSnap.exists()) return { ok: false, error: 'アカウントが見つかりません' };
        if (accSnap.val().passwordHash !== CryptoUtil.simpleHash(password)) return { ok: false, error: 'パスワードが違います' };

        // 新しい名前の重複チェック
        if (newName !== myName) {
            const dupSnap = await this._db.ref('accounts/' + this._encName(newName)).get();
            if (dupSnap.exists()) return { ok: false, error: 'この名前はすでに使用されています' };
        }

        // accounts: 新エントリーを作って旧を削除（名前がキーのため）
        const accData = { ...accSnap.val(), name: newName };
        await this._db.ref('accounts/' + this._encName(newName)).set(accData);
        if (newName !== myName) {
            await this._db.ref('accounts/' + this._encName(myName)).remove();
        }

        // sessions: 名前を更新
        const allSesSnap = await this._db.ref('sessions').get();
        if (allSesSnap.exists()) {
            const updates = {};
            allSesSnap.forEach(c => {
                if (c.val().name === myName) updates[c.key + '/name'] = newName;
            });
            if (Object.keys(updates).length > 0) await this._db.ref('sessions').update(updates);
        }

        // presence: 旧キーを削除して新キーへ
        const presOldSnap = await this._db.ref('presence/' + this._encName(myName)).get();
        if (presOldSnap.exists()) {
            await this._db.ref('presence/' + this._encName(newName)).set(presOldSnap.val());
            if (newName !== myName) await this._db.ref('presence/' + this._encName(myName)).remove();
        }

        // friends: from/to および キー両方を更新（キーは再生成する必要がある）
        // 注: 取得済みスナップショットのキーだけを処理する。新規に作成したキーは触らない。
        const allFrSnap = await this._db.ref('friends').get();
        if (allFrSnap.exists()) {
            const all = allFrSnap.val();
            const originalKeys = Object.keys(all);
            const processedKeys = new Set();
            for (const k of originalKeys) {
                if (processedKeys.has(k)) continue;
                const v = all[k];
                if (!v) continue;
                let changed = false;
                let newVal = { ...v };
                if (v.from === myName) { newVal.from = newName; changed = true; }
                if (v.to === myName) { newVal.to = newName; changed = true; }
                if (changed) {
                    const newKey = this._friendKey(newVal.from, newVal.to);
                    if (newKey !== k) {
                        // 衝突回避: 新キーが既存スナップショット内にある場合は上書きせずスキップ
                        // （通常は newName の重複チェック済みなので起こらない想定）
                        await this._db.ref('friends/' + newKey).set(newVal);
                        await this._db.ref('friends/' + k).remove();
                        processedKeys.add(newKey);
                    } else {
                        await this._db.ref('friends/' + k).update(newVal);
                    }
                    processedKeys.add(k);
                }
            }
        }

        // profiles: 旧キーから新キーへ引っ越し（プロフィール画像が消えないようにする）
        if (newName !== myName) {
            const profOldSnap = await this._db.ref('profiles/' + this._encName(myName)).get();
            if (profOldSnap.exists()) {
                await this._db.ref('profiles/' + this._encName(newName)).set(profOldSnap.val());
                await this._db.ref('profiles/' + this._encName(myName)).remove();
            }
        }

        // signals: 自分宛のシグナルツリーを引っ越し
        const sigOldSnap = await this._db.ref('signals/' + this._encName(myName)).get();
        if (sigOldSnap.exists()) {
            await this._db.ref('signals/' + this._encName(newName)).set(sigOldSnap.val());
            if (newName !== myName) await this._db.ref('signals/' + this._encName(myName)).remove();
        }
        // signals: 送信者名を含むものを更新
        const allSigSnap = await this._db.ref('signals').get();
        if (allSigSnap.exists()) {
            const all = allSigSnap.val();
            for (const recv in all) {
                const sigs = all[recv];
                for (const sid in sigs) {
                    if (sigs[sid] && sigs[sid].from === myName) {
                        await this._db.ref('signals/' + recv + '/' + sid + '/from').set(newName);
                    }
                }
            }
        }

        // groups: members / owner を更新
        const allGSnap = await this._db.ref('groups').get();
        if (allGSnap.exists()) {
            const all = allGSnap.val();
            for (const gid in all) {
                const g = all[gid];
                if (!g) continue;
                let updates = {};
                if (g.owner === myName) updates.owner = newName;
                if (Array.isArray(g.members) && g.members.includes(myName)) {
                    updates.members = g.members.map(m => m === myName ? newName : m);
                }
                if (Object.keys(updates).length > 0) {
                    await this._db.ref('groups/' + gid).update(updates);
                }
            }
        }

        // accepted フレンド全員に「名前を変えた」ことを通知する name_changed シグナル
        // 受信側はこの情報を使ってローカルDM履歴のキーを旧名から新名へマージできる
        if (newName !== myName) {
            try {
                const acceptedPartners = new Set();
                const frSnap2 = await this._db.ref('friends').get();
                if (frSnap2.exists()) {
                    const all = frSnap2.val();
                    for (const k in all) {
                        const v = all[k];
                        if (!v || v.status !== 'accepted') continue;
                        if (v.from === newName) acceptedPartners.add(v.to);
                        else if (v.to === newName) acceptedPartners.add(v.from);
                    }
                }
                const payload = encodeURIComponent(JSON.stringify({ oldName: myName, newName }));
                for (const partner of acceptedPartners) {
                    try {
                        await this.sendSignal(token, partner, 'name_changed', payload);
                    } catch (_) { }
                }
            } catch (_) { }
        }

        return { ok: true, new_name: newName };
    }

    // ----------------- パスワード変更 -----------------
    static async changePassword(token, currentPassword, newPassword) {
        currentPassword = (currentPassword || '').trim();
        newPassword = (newPassword || '').trim();
        if (!token || !currentPassword || !newPassword) return { ok: false, error: 'パラメータが不足しています' };
        if (newPassword.length < 4) return { ok: false, error: 'パスワードは4文字以上で入力してください' };
        if (!/^[a-zA-Z0-9]+$/.test(newPassword)) return { ok: false, error: 'パスワードは半角英数字のみ使用できます' };

        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const accRef = this._db.ref('accounts/' + this._encName(myName));
        const accSnap = await accRef.get();
        if (!accSnap.exists()) return { ok: false, error: 'アカウントが見つかりません' };
        if (accSnap.val().passwordHash !== CryptoUtil.simpleHash(currentPassword)) return { ok: false, error: '現在のパスワードが違います' };

        await accRef.update({ passwordHash: CryptoUtil.simpleHash(newPassword) });
        return { ok: true };
    }

    // ----------------- グループ -----------------
    static async createGroup(token, groupName, avatar) {
        groupName = (groupName || '').trim();
        if (!token || !groupName) return { ok: false, error: 'パラメータが不足しています' };
        if (groupName.length > 20) return { ok: false, error: 'グループ名は20文字以内にしてください' };

        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const ref = this._db.ref('groups').push();
        const groupId = ref.key;
        const data = {
            id: groupId,
            name: groupName,
            owner: myName,
            members: [myName],
            createdAt: this._isoNow()
        };
        if (avatar) data.avatar = avatar;
        await ref.set(data);
        return { ok: true, group_id: groupId, name: groupName };
    }

    static async inviteGroup(token, groupId, target) {
        target = (target || '').trim();
        if (!token || !groupId || !target) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;
        if (!(await this._accountExists(target))) return { ok: false, error: 'ユーザーが見つかりません' };

        const ref = this._db.ref('groups/' + groupId);
        const snap = await ref.get();
        if (!snap.exists()) return { ok: false, error: 'グループが見つかりません' };
        const g = snap.val();
        const members = Array.isArray(g.members) ? g.members : [];
        if (!members.includes(myName)) return { ok: false, error: 'グループに参加していません' };
        if (members.includes(target)) return { ok: false, error: 'すでにメンバーです' };
        members.push(target);
        await ref.update({ members });
        return { ok: true };
    }

    static async leaveGroup(token, groupId) {
        if (!token || !groupId) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const ref = this._db.ref('groups/' + groupId);
        const snap = await ref.get();
        if (!snap.exists()) return { ok: false, error: 'グループが見つかりません' };
        const g = snap.val();
        let members = Array.isArray(g.members) ? g.members : [];
        if (!members.includes(myName)) return { ok: false, error: 'メンバーではありません' };
        members = members.filter(m => m !== myName);
        if (members.length === 0) {
            await ref.remove();
        } else {
            let owner = g.owner;
            if (owner === myName) owner = members[0];
            await ref.update({ owner, members });
        }
        return { ok: true };
    }

    // 招待を受けたユーザーがグループに参加（メンバーリストに自分を追加する）
    // 元のGASでは inviteGroup で既にメンバーに追加されていたが、Firebase版でも同じ仕様にする
    // なので acceptGroupInvite は必要ない（招待時点でメンバー登録される）

    static async getGroups(token) {
        if (!token) return { ok: false, error: 'トークンが必要です' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const allSnap = await this._db.ref('groups').get();
        const groups = [];
        if (allSnap.exists()) {
            const all = allSnap.val();
            for (const gid in all) {
                const g = all[gid];
                if (!g) continue;
                const members = Array.isArray(g.members) ? g.members : [];
                if (members.includes(myName)) {
                    groups.push({
                        id: gid,
                        name: g.name,
                        owner: g.owner,
                        members,
                        avatar: g.avatar || null,
                        activeCall: g.activeCall || null
                    });
                }
            }
        }
        return { ok: true, groups };
    }

    // グループの進行中通話を登録する（ホスト本人が呼ぶ想定）
    // hostPeerId: メッシュ通話用のPeerJS ID（メッシュ参加者が接続するためのID）
    static async setGroupActiveCall(token, groupId, hostName, hostPeerId) {
        if (!token || !groupId || !hostName) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;
        // メンバーチェック
        const groupRef = this._db.ref('groups/' + groupId);
        const gSnap = await groupRef.get();
        if (!gSnap.exists()) return { ok: false, error: 'グループが見つかりません' };
        const g = gSnap.val();
        const members = Array.isArray(g.members) ? g.members : [];
        if (!members.includes(myName)) return { ok: false, error: 'グループに参加していません' };
        // 既に別のホストの通話があるなら拒否（並列通話防止）
        // ただし、自分が新ホストになろうとしている場合は許可（ホスト譲渡）
        if (g.activeCall && g.activeCall.hostName && g.activeCall.hostName !== hostName && g.activeCall.hostName !== myName) {
            return { ok: false, error: '既に別の通話が進行中です', existing: g.activeCall };
        }
        const callData = {
            hostName,
            startedAt: g.activeCall?.startedAt || this._now()
        };
        if (hostPeerId) callData.hostPeerId = hostPeerId;
        await groupRef.child('activeCall').set(callData);
        return { ok: true };
    }

    // グループ通話のホストPeerIDだけ更新する（ホスト譲渡時）
    static async updateGroupCallHost(token, groupId, hostName, hostPeerId) {
        if (!token || !groupId || !hostName || !hostPeerId) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;
        if (myName !== hostName) return { ok: false, error: '自分のみホスト更新できます' };
        const groupRef = this._db.ref('groups/' + groupId);
        const gSnap = await groupRef.get();
        if (!gSnap.exists()) return { ok: false, error: 'グループが見つかりません' };
        const g = gSnap.val();
        const members = Array.isArray(g.members) ? g.members : [];
        if (!members.includes(myName)) return { ok: false, error: 'グループに参加していません' };
        const callData = {
            hostName,
            hostPeerId,
            startedAt: g.activeCall?.startedAt || this._now()
        };
        await groupRef.child('activeCall').set(callData);
        return { ok: true };
    }

    // グループの進行中通話を解除する（ホスト本人が呼ぶ想定）
    static async clearGroupActiveCall(token, groupId) {
        if (!token || !groupId) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;
        const groupRef = this._db.ref('groups/' + groupId);
        const gSnap = await groupRef.get();
        if (!gSnap.exists()) return { ok: false };
        const g = gSnap.val();
        // ホスト本人だけが解除可能
        if (!g.activeCall || g.activeCall.hostName !== myName) return { ok: false, error: 'ホスト権限がありません' };
        await groupRef.child('activeCall').remove();
        // onDisconnect予約も解除
        try { await groupRef.child('activeCall').onDisconnect().cancel(); } catch (_) { }
        return { ok: true };
    }

    // 強制的にグループの活性通話をクリアする（メンバーなら誰でも実行可能、ゾンビ通話復旧用）
    // 必ずメンバーチェックは行う。「明らかに死んだ通話」を回収する用途
    static async forceClearGroupActiveCall(token, groupId) {
        if (!token || !groupId) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;
        const groupRef = this._db.ref('groups/' + groupId);
        const gSnap = await groupRef.get();
        if (!gSnap.exists()) return { ok: false, error: 'グループが見つかりません' };
        const g = gSnap.val();
        const members = Array.isArray(g.members) ? g.members : [];
        if (!members.includes(myName)) return { ok: false, error: 'グループに参加していません' };
        await groupRef.child('activeCall').remove();
        return { ok: true };
    }

    // 自分が切断されたら groups/{gid}/activeCall を自動で削除する
    // （ブラウザを閉じた・タブを閉じた・ネットワーク切断 などに対応）
    static async setupActiveCallOnDisconnect(groupId) {
        if (!groupId) return;
        try {
            const ref = this._db.ref('groups/' + groupId + '/activeCall');
            await ref.onDisconnect().remove();
        } catch (e) {
            console.warn('[mesh] onDisconnect setup failed:', e);
        }
    }

    // onDisconnect予約を解除する（ホスト譲渡時など、自分のセッションが終了しても削除したくない場合）
    static async cancelActiveCallOnDisconnect(groupId) {
        if (!groupId) return;
        try {
            const ref = this._db.ref('groups/' + groupId + '/activeCall');
            await ref.onDisconnect().cancel();
        } catch (e) {
            console.warn('[mesh] onDisconnect cancel failed:', e);
        }
    }

    // groups/{gid}/activeCall の変更を購読する（リアルタイム反映）
    // callback(groupId, activeCallObj|null)
    static subscribeGroupActiveCalls(myName, groupIds, callback) {
        this.unsubscribeGroupActiveCalls();
        this._groupCallSubs = [];
        for (const gid of groupIds) {
            const ref = this._db.ref('groups/' + gid + '/activeCall');
            const handler = ref.on('value', snap => {
                callback(gid, snap.exists() ? snap.val() : null);
            });
            this._groupCallSubs.push({ ref, handler });
        }
    }

    static unsubscribeGroupActiveCalls() {
        if (this._groupCallSubs) {
            for (const { ref, handler } of this._groupCallSubs) {
                try { ref.off('value', handler); } catch (_) { }
            }
            this._groupCallSubs = null;
        }
    }

    // ----------------- プロフィール画像 -----------------
    // dataUrl: data:image/jpeg;base64,... 形式（null で削除）
    static async setMyAvatar(token, dataUrl) {
        if (!token) return { ok: false, error: 'トークンが必要です' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;
        const ref = this._db.ref('profiles/' + this._encName(myName));
        if (dataUrl === null || dataUrl === '') {
            await ref.remove();
        } else {
            await ref.set({ avatar: dataUrl, updatedAt: this._isoNow() });
        }
        return { ok: true };
    }

    // 一人のユーザーのアバターを取得（無ければ null）
    static async getUserAvatar(name) {
        if (!name) return null;
        try {
            const snap = await this._db.ref('profiles/' + this._encName(name) + '/avatar').get();
            return snap.exists() ? snap.val() : null;
        } catch (_) { return null; }
    }

    // 複数ユーザーのアバターを一度に取得 -> { name: dataUrl|null }
    static async getUserAvatars(names) {
        const result = {};
        if (!Array.isArray(names) || names.length === 0) return result;
        await Promise.all(names.map(async n => {
            result[n] = await this.getUserAvatar(n);
        }));
        return result;
    }

    // ----------------- グループ画像 / グループ名変更 -----------------
    static async updateGroupAvatar(token, groupId, dataUrl) {
        if (!token || !groupId) return { ok: false, error: 'パラメータが不足しています' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const ref = this._db.ref('groups/' + groupId);
        const snap = await ref.get();
        if (!snap.exists()) return { ok: false, error: 'グループが見つかりません' };
        const g = snap.val();
        if (g.owner !== myName) return { ok: false, error: 'オーナーのみ変更できます' };

        if (dataUrl === null || dataUrl === '') {
            await ref.child('avatar').remove();
        } else {
            await ref.update({ avatar: dataUrl });
        }
        return { ok: true };
    }

    static async updateGroupName(token, groupId, newName) {
        newName = (newName || '').trim();
        if (!token || !groupId || !newName) return { ok: false, error: 'パラメータが不足しています' };
        if (newName.length > 20) return { ok: false, error: 'グループ名は20文字以内にしてください' };
        const sesSnap = await this._db.ref('sessions/' + token).get();
        if (!sesSnap.exists()) return { ok: false, error: 'セッションが無効です' };
        const myName = sesSnap.val().name;

        const ref = this._db.ref('groups/' + groupId);
        const snap = await ref.get();
        if (!snap.exists()) return { ok: false, error: 'グループが見つかりません' };
        const g = snap.val();
        if (g.owner !== myName) return { ok: false, error: 'オーナーのみ変更できます' };
        await ref.update({ name: newName });
        return { ok: true, new_name: newName };
    }

    // ----------------- ヘルパー -----------------
    // Firebase キーで使えない文字 . $ # [ ] / と空白をエンコード
    static _encName(name) {
        return encodeURIComponent(name).replace(/\./g, '%2E');
    }
    static _decName(enc) {
        try { return decodeURIComponent(enc); } catch (_) { return enc; }
    }
    static _friendKey(a, b) {
        const sorted = [a, b].sort();
        return this._encName(sorted[0]) + '__' + this._encName(sorted[1]);
    }
    static async _accountExists(name) {
        const snap = await this._db.ref('accounts/' + this._encName(name)).get();
        return snap.exists();
    }

    // 全アカウント名を取得（予測候補用）
    static async getAllAccountNames() {
        try {
            const snap = await this._db.ref('accounts').get();
            if (!snap.exists()) return [];
            const names = [];
            const data = snap.val() || {};
            for (const enc of Object.keys(data)) {
                names.push(this._decName(enc));
            }
            return names;
        } catch (_) {
            return [];
        }
    }
    static async _removeSessionsByName(name) {
        const snap = await this._db.ref('sessions').get();
        if (!snap.exists()) return;
        const updates = {};
        snap.forEach(c => {
            if (c.val().name === name) updates[c.key] = null;
        });
        if (Object.keys(updates).length > 0) {
            await this._db.ref('sessions').update(updates);
        }
    }

    // onDisconnect で presence を自動削除（タブを閉じたら即オフラインに）
    static setupPresenceOnDisconnect(name) {
        if (!name) return;
        const presRef = this._db.ref('presence/' + this._encName(name));
        presRef.onDisconnect().remove();
    }

    // =====================================================
    // チャット履歴のクラウド保存（デバイス間同期用）
    // =====================================================
    // 保持期間: 90日（_chatRetentionMs）
    static _chatRetentionMs = 90 * 24 * 60 * 60 * 1000;

    // convKey は "dm:A|B" または "grp:GROUPID" 形式
    // Firebase キー用に変換: ":" や "|" をエスケープ
    static _encConvKey(convKey) {
        if (!convKey) return '';
        // : と | は使えないので置換。元の構造は復元できる必要は無い（キーとして一意であればOK）
        return convKey.replace(/[.#$\[\]\/:|]/g, c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'));
    }

    // メッセージを Firebase に保存
    // convKey: "dm:A|B" または "grp:GROUPID"
    // msg: { msgId, from, content, ts, type, file?, groupId?, ... }
    static async saveChatMessage(convKey, msg) {
        if (!this._db || !convKey || !msg || !msg.msgId) return { ok: false };
        try {
            const encKey = this._encConvKey(convKey);
            const branch = convKey.startsWith('dm:') ? 'dm' : (convKey.startsWith('grp:') ? 'group' : null);
            if (!branch) return { ok: false };
            const ref = this._db.ref('chats/' + branch + '/' + encKey + '/' + msg.msgId);
            // file.data が undefined だと Firebase が拒否するので null 化
            const sanitized = JSON.parse(JSON.stringify(msg));
            await ref.set(sanitized);
            return { ok: true };
        } catch (e) {
            console.warn('[saveChatMessage]', e);
            return { ok: false, error: e?.message };
        }
    }

    // メッセージを Firebase から取得（ts 昇順）
    // sinceTs を渡すとそれ以降のメッセージのみ取得
    static async fetchChatMessages(convKey, sinceTs) {
        if (!this._db || !convKey) return [];
        try {
            const encKey = this._encConvKey(convKey);
            const branch = convKey.startsWith('dm:') ? 'dm' : (convKey.startsWith('grp:') ? 'group' : null);
            if (!branch) return [];
            const ref = this._db.ref('chats/' + branch + '/' + encKey);
            const snap = await ref.get();
            if (!snap.exists()) return [];
            const data = snap.val() || {};
            const cutoff = this._now() - this._chatRetentionMs;
            const arr = [];
            for (const msgId of Object.keys(data)) {
                const m = data[msgId];
                if (!m || typeof m.ts !== 'number') continue;
                if (m.ts < cutoff) continue; // 保持期限切れ
                if (typeof sinceTs === 'number' && m.ts <= sinceTs) continue;
                arr.push(m);
            }
            arr.sort((a, b) => (a.ts || 0) - (b.ts || 0));
            return arr;
        } catch (e) {
            console.warn('[fetchChatMessages]', e);
            return [];
        }
    }

    // メッセージのフィールドを更新（取り消し用）
    // convKey と msgId を指定して特定フィールドだけ書き換え
    static async updateChatMessage(convKey, msgId, patch) {
        if (!this._db || !convKey || !msgId || !patch) return { ok: false };
        try {
            const encKey = this._encConvKey(convKey);
            const branch = convKey.startsWith('dm:') ? 'dm' : (convKey.startsWith('grp:') ? 'group' : null);
            if (!branch) return { ok: false };
            const ref = this._db.ref('chats/' + branch + '/' + encKey + '/' + msgId);
            // 一旦取得して存在確認
            const snap = await ref.get();
            if (!snap.exists()) return { ok: false, error: 'not_found' };
            const sanitized = JSON.parse(JSON.stringify(patch));
            await ref.update(sanitized);
            return { ok: true };
        } catch (e) {
            console.warn('[updateChatMessage]', e);
            return { ok: false, error: e?.message };
        }
    }

    // 保持期限切れメッセージを削除（バックグラウンド）
    // 自分が関わる会話のみ対象
    static async pruneExpiredChats(convKeys) {
        if (!this._db || !Array.isArray(convKeys)) return;
        const cutoff = this._now() - this._chatRetentionMs;
        for (const convKey of convKeys) {
            try {
                const encKey = this._encConvKey(convKey);
                const branch = convKey.startsWith('dm:') ? 'dm' : (convKey.startsWith('grp:') ? 'group' : null);
                if (!branch) continue;
                const ref = this._db.ref('chats/' + branch + '/' + encKey);
                const snap = await ref.get();
                if (!snap.exists()) continue;
                const data = snap.val() || {};
                const updates = {};
                for (const msgId of Object.keys(data)) {
                    const m = data[msgId];
                    if (!m || typeof m.ts !== 'number') continue;
                    if (m.ts < cutoff) updates[msgId] = null;
                }
                if (Object.keys(updates).length > 0) {
                    await ref.update(updates);
                }
            } catch (e) {
                console.warn('[pruneExpiredChats]', convKey, e);
            }
        }
    }
}

// =====================================================
// メインアプリケーション
// =====================================================
class SecureVideoChat {
    constructor() {
        // 認証情報
        this.token = localStorage.getItem('svc_token') || null;
        this.myName = localStorage.getItem('svc_name') || null;

        // 自動ログイン設定
        this.autoLoginEnabled = localStorage.getItem('svc_autologin') === '1';

        // 設定
        this.settings = JSON.parse(localStorage.getItem('svc_settings') || '{}');

        // フレンドリスト（キャッシュ）
        this.friendNames = new Set();
        this.pendingFriendSignal = null;

        // DM・グループチャット
        this.dmPartner = null;
        this.dmPeerConns = {};
        this.localChatDB = {};
        this._loadLocalChatDB();
        // 未読判定用: 各会話キーごとの「最終既読時刻(ts)」を localStorage に永続化
        // 構造: { "dm:userA|userB": 1700000000000, "grp:xxx": 1700000000000 }
        this.lastReadTs = {};
        this._loadLastReadTs();
        this.dmUnreadCounts = {};
        this.groupUnreadCounts = {};
        this.currentGroupId = null;
        this.currentGroupName = null;
        this.myGroups = [];
        this.pendingGroupInvite = null;

        // ブロック
        this.blockedUsers = new Set(JSON.parse(localStorage.getItem('svc_blocked') || '[]'));

        // アバターキャッシュ（メモリ）: { name: dataUrl|null }
        this.avatarCache = {};
        // localStorage から復元
        try {
            const cached = JSON.parse(localStorage.getItem('svc_avatar_cache') || '{}');
            if (cached && typeof cached === 'object') this.avatarCache = cached;
        } catch (_) { }
        this.myAvatar = this.avatarCache[this.myName] || null;
        // グループアバターキャッシュ: { groupId: dataUrl|null }
        this.groupAvatarCache = {};

        // PeerJS / 通話
        this.peer = null;
        this.currentCall = null;
        this.dataConnection = null;
        this.localStream = null;
        this.encryptionKey = null;
        this.isAudioEnabled = true;
        this.isVideoEnabled = false; // カメラはOFFスタート（要件1）
        this.isMediaReady = false;
        this.isScreenSharing = false;
        this.savedCameraTrack = null; // 画面共有中に元のカメラトラックを退避
        this.remoteCameraOff = false; // 相手のカメラ状態
        this.audioContext = null;
        this.gainNode = null;
        this.currentVolume = 100;
        this.disconnectedBySelf = false;
        this.isDisconnecting = false;
        this.isVolumeControlVisible = false;
        this.isKeyVisible = false;

        // シグナリング
        this.heartbeatInterval = null;
        this.onlineListInterval = null;
        this.pendingSignal = null;
        this.callTargetName = null;
        this._processedSignalIds = new Set();

        // ===== メッシュ通話用 =====
        this.meshPeer = null;
        this.meshMyId = null;
        this.meshPeers = new Map();         // peerId -> {call, conn, name, stream, micOn, camOn, screenSharing}
        this.meshRoomId = null;             // ルームID = ホストの本名
        this.meshHostName = null;
        this.meshIsHost = false;
        this.meshGroupId = null;            // グループ通話のとき
        this.meshGroupName = null;
        this.meshMicOn = true;
        this.meshCamOn = false;             // カメラはOFFスタート（既存仕様踏襲）
        this.meshIsScreenSharing = false;
        this.meshSavedCameraTrack = null;
        this.outgoingMeshInvitees = new Set();
        this.pendingMeshInvite = null;
        // 進行中のグループ通話の追跡: groupId -> { hostName, startedAt }
        this.activeGroupCalls = new Map();

        // Firebase 初期化
        try {
            FbAPI.init();
        } catch (e) {
            console.error('[Firebase初期化エラー]', e);
            alert('Firebaseの初期化に失敗しました。firebase-config.js を確認してください。\n\n' + e.message);
            return;
        }

        this.initElements();
        this.setupAuthEvents();
        this.setupMainEvents();
        this.setupPermissionModal();
        this.applyAutoLoginCheck();

        if (this.token && this.myName) {
            this.validateSessionAndEnter();
        }

        window.addEventListener('beforeunload', () => this.onBeforeUnload());
    }

    // =====================================================
    // 要素取得
    // =====================================================
    initElements() {
        this.el = {
            authScreen: document.getElementById('authScreen'),
            mainScreen: document.getElementById('mainScreen'),

            loginForm: document.getElementById('loginForm'),
            registerForm: document.getElementById('registerForm'),
            loginName: document.getElementById('loginName'),
            loginPassword: document.getElementById('loginPassword'),
            loginBtn: document.getElementById('loginBtn'),
            loginError: document.getElementById('loginError'),
            registerName: document.getElementById('registerName'),
            registerPassword: document.getElementById('registerPassword'),
            registerBtn: document.getElementById('registerBtn'),
            registerError: document.getElementById('registerError'),

            headerUserName: document.getElementById('headerUserName'),
            logoutBtn: document.getElementById('logoutBtn'),
            connectionStatus: document.getElementById('connectionStatus'),
            statusIndicator: document.getElementById('statusIndicator'),
            securityToggleBtn: document.getElementById('securityToggleBtn'),
            securityPanel: document.getElementById('securityPanel'),
            localPeerId: document.getElementById('localPeerId'),
            encryptionKey: document.getElementById('encryptionKey'),

            userList: document.getElementById('userList'),
            refreshListBtn: document.getElementById('refreshListBtn'),

            waitingState: document.getElementById('waitingState'),
            videoGrid: document.getElementById('videoGrid'),
            localVideo: document.getElementById('localVideo'),
            remoteVideo: document.getElementById('remoteVideo'),
            localName: document.getElementById('localName'),
            remoteName: document.getElementById('remoteName'),
            callControls: document.getElementById('callControls'),
            disconnectButton: document.getElementById('disconnectButton'),
            toggleMicButton: document.getElementById('toggleMicButton'),
            toggleVideoButton: document.getElementById('toggleVideoButton'),
            screenShareButton: document.getElementById('screenShareButton'),
            localAvatarOverlay: document.getElementById('localAvatarOverlay'),
            localAvatarCircle: document.getElementById('localAvatarCircle'),
            localAvatarInitial: document.getElementById('localAvatarInitial'),
            remoteAvatarOverlay: document.getElementById('remoteAvatarOverlay'),
            remoteAvatarCircle: document.getElementById('remoteAvatarCircle'),
            remoteAvatarInitial: document.getElementById('remoteAvatarInitial'),
            msgActionMenu: document.getElementById('msgActionMenu'),
            msgRecallBtn: document.getElementById('msgRecallBtn'),
            recallConfirmModal: document.getElementById('recallConfirmModal'),
            recallConfirmBtn: document.getElementById('recallConfirmBtn'),
            recallCancelBtn: document.getElementById('recallCancelBtn'),
            connectionQuality: document.getElementById('connectionQuality'),
            volumeControlButton: document.getElementById('volumeControlButton'),
            volumeSlider: document.getElementById('volumeSlider'),
            volumeSliderContainer: document.querySelector('.volume-slider-container'),
            volumeValue: document.getElementById('volumeValue'),
            boostBadge: document.getElementById('boostBadge'),

            incomingCallModal: document.getElementById('incomingCallModal'),
            incomingCallerName: document.getElementById('incomingCallerName'),
            acceptCallBtn: document.getElementById('acceptCallBtn'),
            rejectCallBtn: document.getElementById('rejectCallBtn'),
            callingModal: document.getElementById('callingModal'),
            callingTargetName: document.getElementById('callingTargetName'),
            cancelCallBtn: document.getElementById('cancelCallBtn'),
            notificationModal: document.getElementById('notificationModal'),
            permissionModal: document.getElementById('permissionModal'),
            permissionStartBtn: document.getElementById('permissionStartBtn'),
            permissionCloseBtn: document.getElementById('permissionCloseBtn'),

            shiftShortcutUrl: document.getElementById('shiftShortcutUrl'),
            saveShortcutBtn: document.getElementById('saveShortcutBtn'),
            shortcutSavedMsg: document.getElementById('shortcutSavedMsg'),

            autoLoginCheck: document.getElementById('autoLoginCheck'),
            autoLoginOverlay: document.getElementById('autoLoginOverlay'),
            autoLoginName: document.getElementById('autoLoginName'),
            autoLoginStatus: document.getElementById('autoLoginStatus'),

            friendBtn: document.getElementById('friendBtn'),
            friendRequestBadge: document.getElementById('friendRequestBadge'),
            friendModal: document.getElementById('friendModal'),
            friendList: document.getElementById('friendList'),
            incomingRequests: document.getElementById('incomingRequests'),
            outgoingRequests: document.getElementById('outgoingRequests'),
            friendSearchInput: document.getElementById('friendSearchInput'),
            sendFriendRequestBtn: document.getElementById('sendFriendRequestBtn'),
            friendAddError: document.getElementById('friendAddError'),
            requestTabBadge: document.getElementById('requestTabBadge'),

            settingsBtn: document.getElementById('settingsBtn'),
            settingsModal: document.getElementById('settingsModal'),
            settingsAutoLogin: document.getElementById('settingsAutoLogin'),
            settingsSaveBtn: document.getElementById('settingsSaveBtn'),
            settingsNewName: document.getElementById('settingsNewName'),
            settingsNameCurrentPw: document.getElementById('settingsNameCurrentPw'),
            settingsChangeNameBtn: document.getElementById('settingsChangeNameBtn'),
            settingsNameError: document.getElementById('settingsNameError'),
            settingsCurrentPw: document.getElementById('settingsCurrentPw'),
            settingsNewPw: document.getElementById('settingsNewPw'),
            settingsNewPwConfirm: document.getElementById('settingsNewPwConfirm'),
            settingsChangePwBtn: document.getElementById('settingsChangePwBtn'),
            settingsPwError: document.getElementById('settingsPwError'),

            incomingFriendRequestModal: document.getElementById('incomingFriendRequestModal'),
            friendRequestFromName: document.getElementById('friendRequestFromName'),
            acceptFriendRequestBtn: document.getElementById('acceptFriendRequestBtn'),
            rejectFriendRequestBtn: document.getElementById('rejectFriendRequestBtn'),

            dmBtn: document.getElementById('dmBtn'),
            dmBadge: document.getElementById('dmBadge'),
            dmModal: document.getElementById('dmModal'),
            dmModalTitle: document.getElementById('dmModalTitle'),
            dmConversationList: document.getElementById('dmConversationList'),
            dmChatArea: document.getElementById('dmChatArea'),
            dmBackBtn: document.getElementById('dmBackBtn'),
            dmMessages: document.getElementById('dmMessages'),
            dmInput: document.getElementById('dmInput'),
            dmSendBtn: document.getElementById('dmSendBtn'),
            dmFileInput: document.getElementById('dmFileInput'),
            dmCallBtn: document.getElementById('dmCallBtn'),

            // 新規DM
            newDmFab: document.getElementById('newDmFab'),
            newDmModal: document.getElementById('newDmModal'),
            newDmTargetName: document.getElementById('newDmTargetName'),
            newDmError: document.getElementById('newDmError'),
            newDmConfirmBtn: document.getElementById('newDmConfirmBtn'),
            newDmCancelBtn: document.getElementById('newDmCancelBtn'),

            groupBtn: document.getElementById('groupBtn'),
            groupBadge: document.getElementById('groupBadge'),
            groupModal: document.getElementById('groupModal'),
            groupModalTitle: document.getElementById('groupModalTitle'),
            groupListArea: document.getElementById('groupListArea'),
            groupChatArea: document.getElementById('groupChatArea'),
            groupBackBtn: document.getElementById('groupBackBtn'),
            groupChatName: document.getElementById('groupChatName'),
            groupMessages: document.getElementById('groupMessages'),
            groupInput: document.getElementById('groupInput'),
            groupSendBtn: document.getElementById('groupSendBtn'),
            groupFileInput: document.getElementById('groupFileInput'),
            createGroupBtn: document.getElementById('createGroupBtn'),
            inviteGroupBtn: document.getElementById('inviteGroupBtn'),
            leaveGroupBtn: document.getElementById('leaveGroupBtn'),
            createGroupModal: document.getElementById('createGroupModal'),
            newGroupName: document.getElementById('newGroupName'),
            createGroupConfirmBtn: document.getElementById('createGroupConfirmBtn'),
            createGroupCancelBtn: document.getElementById('createGroupCancelBtn'),
            createGroupError: document.getElementById('createGroupError'),
            inviteGroupModal: document.getElementById('inviteGroupModal'),
            inviteTargetName: document.getElementById('inviteTargetName'),
            inviteGroupConfirmBtn: document.getElementById('inviteGroupConfirmBtn'),
            inviteGroupCancelBtn: document.getElementById('inviteGroupCancelBtn'),
            inviteGroupError: document.getElementById('inviteGroupError'),
            incomingGroupInviteModal: document.getElementById('incomingGroupInviteModal'),
            groupInviteFrom: document.getElementById('groupInviteFrom'),
            groupInviteName: document.getElementById('groupInviteName'),
            acceptGroupInviteBtn: document.getElementById('acceptGroupInviteBtn'),
            rejectGroupInviteBtn: document.getElementById('rejectGroupInviteBtn'),

            blockSearchInput: document.getElementById('blockSearchInput'),
            addBlockBtn: document.getElementById('addBlockBtn'),
            blockError: document.getElementById('blockError'),
            blockList: document.getElementById('blockList'),

            // プロフィール画像（設定モーダル内）
            avatarPreview: document.getElementById('avatarPreview'),
            avatarPreviewInitial: document.getElementById('avatarPreviewInitial'),
            avatarFileInput: document.getElementById('avatarFileInput'),
            avatarRemoveBtn: document.getElementById('avatarRemoveBtn'),
            avatarError: document.getElementById('avatarError'),

            // グループ作成モーダルの画像
            newGroupAvatarPreview: document.getElementById('newGroupAvatarPreview'),
            newGroupAvatarInput: document.getElementById('newGroupAvatarInput'),
            newGroupAvatarRemoveBtn: document.getElementById('newGroupAvatarRemoveBtn'),

            // グループ設定モーダル
            groupSettingsBtn: document.getElementById('groupSettingsBtn'),
            groupSettingsModal: document.getElementById('groupSettingsModal'),
            groupSettingsCloseBtn: document.getElementById('groupSettingsCloseBtn'),
            groupSettingsHint: document.getElementById('groupSettingsHint'),
            groupSettingsAvatarPreview: document.getElementById('groupSettingsAvatarPreview'),
            groupSettingsAvatarInput: document.getElementById('groupSettingsAvatarInput'),
            groupSettingsAvatarUploadLabel: document.getElementById('groupSettingsAvatarUploadLabel'),
            groupSettingsAvatarRemoveBtn: document.getElementById('groupSettingsAvatarRemoveBtn'),
            groupSettingsName: document.getElementById('groupSettingsName'),
            groupSettingsSaveBtn: document.getElementById('groupSettingsSaveBtn'),
            groupSettingsError: document.getElementById('groupSettingsError'),
        };
    }

    setupPermissionModal() {
        const CONSENT_KEY = 'svc_permission_consented';
        const modal = this.el.permissionModal;
        const startBtn = this.el.permissionStartBtn;
        const closeBtn = this.el.permissionCloseBtn;

        if (!modal) return;

        const alreadyConsented = localStorage.getItem(CONSENT_KEY) === '1';

        if (!alreadyConsented) {
            modal.classList.add('visible');
            if (closeBtn) closeBtn.style.display = 'none';
        }

        if (startBtn) {
            startBtn.addEventListener('click', () => {
                modal.classList.remove('visible');
                localStorage.setItem(CONSENT_KEY, '1');
                const testPopup = window.open('', '_blank', 'width=1,height=1');
                if (testPopup) testPopup.close();
            });
        }

        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                if (localStorage.getItem(CONSENT_KEY) === '1') {
                    modal.classList.remove('visible');
                }
            });
        }
    }

    applyAutoLoginCheck() {
        if (this.el.autoLoginCheck) {
            this.el.autoLoginCheck.checked = this.autoLoginEnabled;
        }
    }

    setupAuthEvents() {
        document.querySelectorAll('.auth-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                const target = tab.dataset.tab;
                this.el.loginForm.style.display = target === 'login' ? '' : 'none';
                this.el.registerForm.style.display = target === 'register' ? '' : 'none';
                this.el.loginError.textContent = '';
                this.el.registerError.textContent = '';
            });
        });

        document.querySelectorAll('.pw-toggle-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const input = document.getElementById(btn.dataset.target);
                const icon = btn.querySelector('i');
                if (input.type === 'password') {
                    input.type = 'text';
                    icon.className = 'fas fa-eye';
                } else {
                    input.type = 'password';
                    icon.className = 'fas fa-eye-slash';
                }
            });
        });

        this.el.loginBtn.addEventListener('click', () => this.doLogin());
        this.el.loginPassword.addEventListener('keydown', e => { if (e.key === 'Enter') this.doLogin(); });
        this.el.loginName.addEventListener('keydown', e => { if (e.key === 'Enter') this.el.loginPassword.focus(); });

        this.el.registerBtn.addEventListener('click', () => this.doRegister());
        this.el.registerPassword.addEventListener('keydown', e => { if (e.key === 'Enter') this.doRegister(); });
        this.el.registerName.addEventListener('input', e => {
            const cleaned = e.target.value.replace(/[\s\u3000]/g, '');
            if (cleaned !== e.target.value) {
                e.target.value = cleaned;
                this.el.registerError.textContent = '名前にスペース（半角・全角）は使用できません';
            }
        });
    }

    async validateSessionAndEnter() {
        if (!this.autoLoginEnabled) {
            this.clearLocalSession();
            return;
        }

        this._showAutoLoginOverlay('セッションを確認中...');

        try {
            const res = await FbAPI.heartbeat(this.token, '');
            if (res.ok) {
                this._setAutoLoginStatus('ログイン中...');
                this.enterMainScreen();
            } else {
                this._hideAutoLoginOverlay();
                this.clearLocalSession();
            }
        } catch (e) {
            this._hideAutoLoginOverlay();
            this.clearLocalSession();
        }
    }

    _showAutoLoginOverlay(status) {
        const overlay = this.el.autoLoginOverlay;
        if (!overlay) return;
        if (this.el.autoLoginName) this.el.autoLoginName.textContent = this.myName || '';
        if (this.el.autoLoginStatus) this.el.autoLoginStatus.textContent = status;
        overlay.style.display = 'flex';
    }

    _setAutoLoginStatus(status) {
        if (this.el.autoLoginStatus) this.el.autoLoginStatus.textContent = status;
    }

    _hideAutoLoginOverlay() {
        if (this.el.autoLoginOverlay) this.el.autoLoginOverlay.style.display = 'none';
    }

    clearLocalSession() {
        this.token = null;
        this.myName = null;
        localStorage.removeItem('svc_token');
        localStorage.removeItem('svc_name');
        this.autoLoginEnabled = false;
        localStorage.setItem('svc_autologin', '0');
    }

    async doLogin() {
        const name = this.el.loginName.value.trim();
        const password = this.el.loginPassword.value.trim();
        this.el.loginError.textContent = '';

        if (!name || !password) {
            this.el.loginError.textContent = '本名とパスワードを入力してください';
            return;
        }

        this.el.loginBtn.disabled = true;
        this.el.loginBtn.textContent = 'ログイン中...';

        try {
            const res = await FbAPI.login(name, password, '');
            if (res.ok) {
                this.token = res.token;
                this.myName = res.name;
                localStorage.setItem('svc_token', this.token);
                localStorage.setItem('svc_name', this.myName);
                const autoLogin = this.el.autoLoginCheck?.checked || false;
                this.autoLoginEnabled = autoLogin;
                localStorage.setItem('svc_autologin', autoLogin ? '1' : '0');
                this.enterMainScreen();
            } else {
                this.el.loginError.textContent = res.error || 'ログインに失敗しました';
            }
        } catch (e) {
            console.error(e);
            this.el.loginError.textContent = 'サーバーへの接続に失敗しました';
        }

        this.el.loginBtn.disabled = false;
        this.el.loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> ログイン';
    }

    async doRegister() {
        const name = this.el.registerName.value.trim();
        const password = this.el.registerPassword.value.trim();
        this.el.registerError.textContent = '';

        if (!name) { this.el.registerError.textContent = '本名を入力してください'; return; }
        if (/[\s\u3000]/.test(name)) { this.el.registerError.textContent = '名前にスペース（半角・全角）は使用できません'; return; }
        if (!password || password.length < 4) { this.el.registerError.textContent = 'パスワードは4文字以上で入力してください'; return; }
        if (!/^[a-zA-Z0-9]+$/.test(password)) { this.el.registerError.textContent = 'パスワードは半角英数字のみです'; return; }

        this.el.registerBtn.disabled = true;
        this.el.registerBtn.textContent = '登録中...';

        try {
            const res = await FbAPI.register(name, password);
            if (res.ok) {
                const loginRes = await FbAPI.login(name, password, '');
                if (loginRes.ok) {
                    this.token = loginRes.token;
                    this.myName = loginRes.name;
                    localStorage.setItem('svc_token', this.token);
                    localStorage.setItem('svc_name', this.myName);
                    this.enterMainScreen();
                } else {
                    document.querySelector('[data-tab="login"]').click();
                    this.el.loginName.value = name;
                }
            } else {
                this.el.registerError.textContent = res.error || '登録に失敗しました';
            }
        } catch (e) {
            console.error(e);
            this.el.registerError.textContent = 'サーバーへの接続に失敗しました';
        }

        this.el.registerBtn.disabled = false;
        this.el.registerBtn.innerHTML = '<i class="fas fa-user-plus"></i> アカウントを作成';
    }

    async enterMainScreen() {
        this._hideAutoLoginOverlay();
        this.el.authScreen.style.display = 'none';
        this.el.mainScreen.style.display = '';
        this.el.headerUserName.textContent = this.myName;
        this.el.localName.textContent = this.myName;

        this.updateStatus('初期化中...');

        // 未読状態を localStorage から復元してバッジを再計算
        // （myName 確定後に呼ぶ必要がある）
        this._loadLastReadTs();
        this._recomputeAllUnreadBadges();

        // 自分のアバターを読み込み（バックグラウンド）
        this._loadMyAvatar();

        // グループ一覧を取得してから未読を再計算（グループバッジが正しく出るように）
        // _loadGroups は activeCall 同期と購読も行う
        this._loadGroups().then(() => {
            this._recomputeAllUnreadBadges();
            // グループ一覧が揃った後、クラウドからチャット履歴を取り込む（バックグラウンド）
            this._syncChatHistoryFromCloud().catch(() => { });
        }).catch(() => { });

        // フレンドリスト取得
        FbAPI.getFriends(this.token).then(friendRes => {
            if (friendRes?.ok) {
                this.friendNames = new Set([
                    ...(friendRes.friends || []),
                    ...(friendRes.incoming || []).map(r => r.from),
                ]);
                this._updateFriendBadge((friendRes.incoming || []).length);
                this._cachedFriendData = friendRes;
                // フレンドが分かった時点で DM 履歴の取り込みも開始（重複呼び出しは内部でガード）
                this._syncChatHistoryFromCloud().catch(() => { });
            }
        }).catch(() => { });

        // friends ノードのリアルタイム購読を開始
        // （相手が名前を変えたりフレンド操作したときに自動でこちらのUIが追従する）
        this.subscribeFriendStream();

        // onDisconnect で presence を自動削除
        FbAPI.setupPresenceOnDisconnect(this.myName);

        // シグナルのリアルタイム購読を開始
        this.subscribeSignalStream();

        try {
            await this.initializePeer();
            this.isMediaReady = false;
            this.startHeartbeat();
            this.startOnlineListPolling();
            await this.refreshOnlineList();
        } catch (e) {
            console.error('初期化エラー:', e);
        }
    }

    setupMainEvents() {
        this.el.logoutBtn.addEventListener('click', () => {
            // 自動ログインが有効な状態で初めてログアウトする場合のみ警告
            if (this.autoLoginEnabled && localStorage.getItem('svc_logout_warned') !== '1') {
                const ok = confirm('ここでログアウトをすると、自動ログインが作動しなくなります。よろしいですか？');
                if (!ok) return;
                localStorage.setItem('svc_logout_warned', '1');
            }
            this.doLogout();
        });

        this.el.securityToggleBtn.addEventListener('click', () => {
            this.el.securityPanel.classList.toggle('collapsed');
            this.el.securityToggleBtn.classList.toggle('active');
        });

        if (this.el.friendBtn) {
            this.el.friendBtn.addEventListener('click', () => this.openFriendModal());
        }
        document.querySelector('.friend-modal-close')?.addEventListener('click', () => {
            this.el.friendModal.classList.remove('visible');
        });

        document.querySelectorAll('.friend-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.friend-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                const target = tab.dataset.ftab;
                document.getElementById('friendListPanel').style.display = target === 'friends' ? '' : 'none';
                document.getElementById('requestsPanel').style.display = target === 'requests' ? '' : 'none';
                document.getElementById('addFriendPanel').style.display = target === 'add' ? '' : 'none';
                document.getElementById('blockPanel').style.display = target === 'block' ? '' : 'none';
                if (target === 'block') this._renderBlockList();
            });
        });

        if (this.el.sendFriendRequestBtn) {
            this.el.sendFriendRequestBtn.addEventListener('click', () => this.sendFriendRequest());
        }
        if (this.el.friendSearchInput) {
            this.el.friendSearchInput.addEventListener('keydown', e => { if (e.key === 'Enter') this.sendFriendRequest(); });
        }

        // ===== ユーザー名候補（カスタムドロップダウン） =====
        // data-suggest-users="true" を持つ全ての input にbind
        document.querySelectorAll('input[data-suggest-users="true"]').forEach(inp => {
            this._bindSuggestInput(inp);
        });

        if (this.el.acceptFriendRequestBtn) {
            this.el.acceptFriendRequestBtn.addEventListener('click', () => this.handleIncomingFriendRequest(true));
        }
        if (this.el.rejectFriendRequestBtn) {
            this.el.rejectFriendRequestBtn.addEventListener('click', () => this.handleIncomingFriendRequest(false));
        }

        if (this.el.settingsBtn) {
            this.el.settingsBtn.addEventListener('click', () => this.openSettingsModal());
        }
        document.querySelector('.settings-modal-close')?.addEventListener('click', () => {
            this.el.settingsModal.classList.remove('visible');
        });
        if (this.el.settingsSaveBtn) {
            this.el.settingsSaveBtn.addEventListener('click', () => this.saveSettings());
        }
        if (this.el.settingsChangeNameBtn) {
            this.el.settingsChangeNameBtn.addEventListener('click', () => this.doChangeName());
        }
        if (this.el.settingsChangePwBtn) {
            this.el.settingsChangePwBtn.addEventListener('click', () => this.doChangePassword());
        }
        // 管理者: 一斉DM
        const adminBroadcastBtn = document.getElementById('adminBroadcastBtn');
        if (adminBroadcastBtn) {
            adminBroadcastBtn.addEventListener('click', () => this.doAdminBroadcast());
        }

        document.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const input = document.getElementById(btn.dataset.target);
                input.select();
                document.execCommand('copy');
                this.showNotification('成功', 'コピーしました', 'success');
            });
        });

        const visToggle = document.querySelector('.toggle-visibility-btn');
        if (visToggle) {
            visToggle.addEventListener('click', () => {
                this.isKeyVisible = !this.isKeyVisible;
                this.el.encryptionKey.type = this.isKeyVisible ? 'text' : 'password';
                visToggle.querySelector('i').className = this.isKeyVisible ? 'fas fa-eye' : 'fas fa-eye-slash';
            });
        }

        this.el.refreshListBtn.addEventListener('click', () => this.refreshOnlineList());

        this.el.disconnectButton.addEventListener('click', () => {
            if (this.isDisconnecting) return;
            this.el.disconnectButton.disabled = true;
            this.el.disconnectButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 切断中...';
            this.disconnectedBySelf = true;
            // メッシュ通話を終了
            this.disconnect();
        });
        this.el.toggleMicButton.addEventListener('click', () => this.toggleAudio());
        this.el.toggleVideoButton.addEventListener('click', () => this.toggleVideo());
        if (this.el.screenShareButton) {
            this.el.screenShareButton.addEventListener('click', () => this.toggleScreenShare());
        }
        // メッシュ通話招待ボタン
        const meshInviteBtn = document.getElementById('meshInviteBtn');
        if (meshInviteBtn) {
            meshInviteBtn.addEventListener('click', () => this.showInviteFriendModal());
        }
        const meshInviteCloseBtn = document.getElementById('meshInviteCloseBtn');
        if (meshInviteCloseBtn) {
            meshInviteCloseBtn.addEventListener('click', () => this.hideInviteFriendModal());
        }
        this.el.volumeControlButton.addEventListener('click', () => this.toggleVolumeControl());
        this.el.volumeSlider.addEventListener('input', e => this.updateVolume(e.target.value));

        this.el.acceptCallBtn.addEventListener('click', () => this.acceptIncomingCall());
        this.el.rejectCallBtn.addEventListener('click', () => this.rejectIncomingCall());

        this.el.cancelCallBtn.addEventListener('click', () => this.cancelOutgoingCall());

        document.querySelector('.modal-close').addEventListener('click', () => {
            this.el.notificationModal.classList.remove('visible');
        });

        document.addEventListener('click', e => {
            if (this.el.volumeSliderContainer &&
                !this.el.volumeSliderContainer.contains(e.target) &&
                !this.el.volumeControlButton.contains(e.target)) {
                this.isVolumeControlVisible = false;
                this.el.volumeSliderContainer.classList.remove('visible');
            }
        });

        const STORAGE_KEY = 'svc_shortcut_url';
        const DEFAULT_URL = 'https://manaviewer.jp/';
        const savedUrl = localStorage.getItem(STORAGE_KEY);
        if (this.el.shiftShortcutUrl) this.el.shiftShortcutUrl.value = savedUrl || DEFAULT_URL;

        if (this.el.saveShortcutBtn) {
            this.el.saveShortcutBtn.addEventListener('click', () => {
                const url = this.el.shiftShortcutUrl.value.trim();
                if (url) {
                    localStorage.setItem(STORAGE_KEY, url);
                    this.el.shortcutSavedMsg.classList.add('visible');
                    setTimeout(() => this.el.shortcutSavedMsg.classList.remove('visible'), 1500);
                }
            });
        }

        let shiftTimes = [];
        document.addEventListener('keydown', e => {
            if (e.key !== 'Shift') return;
            const now = Date.now();
            shiftTimes.push(now);
            shiftTimes = shiftTimes.filter(t => now - t < 1000);
            if (shiftTimes.length >= 3) {
                shiftTimes = [];
                const url = localStorage.getItem(STORAGE_KEY) || DEFAULT_URL;
                const w = window.screen.availWidth;
                const h = window.screen.availHeight;
                window.open(url, '_blank', `width=${w},height=${h},left=0,top=0,noopener`);
                this.updateVolume(0);
                if (this.el.volumeSlider) this.el.volumeSlider.value = 0;
            }
        });

        // DM
        if (this.el.dmBtn) this.el.dmBtn.addEventListener('click', () => this.openDmModal());
        document.querySelector('.dm-modal-close')?.addEventListener('click', () => {
            this.el.dmModal.classList.remove('visible');
        });
        if (this.el.dmBackBtn) this.el.dmBackBtn.addEventListener('click', () => this._showDmConversationList());
        if (this.el.dmSendBtn) this.el.dmSendBtn.addEventListener('click', () => this._sendDmMessage());
        if (this.el.dmInput) this.el.dmInput.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this._sendDmMessage(); } });
        if (this.el.dmFileInput) this.el.dmFileInput.addEventListener('change', e => this._sendDmFile(e.target.files[0]));
        if (this.el.dmCallBtn) this.el.dmCallBtn.addEventListener('click', () => {
            if (this.dmPartner) {
                this.el.dmModal.classList.remove('visible');
                // メッシュ通話ではpeerIdは不要（招待者本名で接続）
                this.startOutgoingCall(this.dmPartner, null);
            }
        });

        // 新規DM
        if (this.el.newDmFab) this.el.newDmFab.addEventListener('click', () => {
            if (this.el.newDmTargetName) this.el.newDmTargetName.value = '';
            if (this.el.newDmError) this.el.newDmError.textContent = '';
            this.el.newDmModal.classList.add('visible');
            setTimeout(() => this.el.newDmTargetName?.focus(), 50);
        });
        if (this.el.newDmCancelBtn) this.el.newDmCancelBtn.addEventListener('click', () => {
            this.el.newDmModal.classList.remove('visible');
        });
        if (this.el.newDmConfirmBtn) this.el.newDmConfirmBtn.addEventListener('click', () => this._startNewDm());
        if (this.el.newDmTargetName) this.el.newDmTargetName.addEventListener('keydown', e => {
            if (e.key === 'Enter') { e.preventDefault(); this._startNewDm(); }
        });

        // グループ
        if (this.el.groupBtn) this.el.groupBtn.addEventListener('click', () => this.openGroupModal());
        document.querySelector('.group-modal-close')?.addEventListener('click', () => {
            this.el.groupModal.classList.remove('visible');
        });
        if (this.el.groupBackBtn) this.el.groupBackBtn.addEventListener('click', () => this._showGroupList());
        if (this.el.createGroupBtn) this.el.createGroupBtn.addEventListener('click', () => {
            if (this.el.newGroupName) this.el.newGroupName.value = '';
            if (this.el.createGroupError) this.el.createGroupError.textContent = '';
            this._clearNewGroupAvatar();
            this.el.createGroupModal.classList.add('visible');
        });
        if (this.el.createGroupConfirmBtn) this.el.createGroupConfirmBtn.addEventListener('click', () => this._createGroup());
        if (this.el.createGroupCancelBtn) this.el.createGroupCancelBtn.addEventListener('click', () => this.el.createGroupModal.classList.remove('visible'));
        if (this.el.newGroupAvatarInput) this.el.newGroupAvatarInput.addEventListener('change', e => this._onNewGroupAvatarSelected(e.target.files[0]));
        if (this.el.newGroupAvatarRemoveBtn) this.el.newGroupAvatarRemoveBtn.addEventListener('click', () => this._clearNewGroupAvatar());
        if (this.el.groupSendBtn) this.el.groupSendBtn.addEventListener('click', () => this._sendGroupMessage());
        if (this.el.groupInput) this.el.groupInput.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this._sendGroupMessage(); } });
        if (this.el.groupFileInput) this.el.groupFileInput.addEventListener('change', e => this._sendGroupFile(e.target.files[0]));
        if (this.el.inviteGroupBtn) this.el.inviteGroupBtn.addEventListener('click', () => {
            if (this.el.inviteTargetName) this.el.inviteTargetName.value = '';
            if (this.el.inviteGroupError) this.el.inviteGroupError.textContent = '';
            this.el.inviteGroupModal.classList.add('visible');
        });
        if (this.el.inviteGroupConfirmBtn) this.el.inviteGroupConfirmBtn.addEventListener('click', () => this._inviteGroup());
        if (this.el.inviteGroupCancelBtn) this.el.inviteGroupCancelBtn.addEventListener('click', () => this.el.inviteGroupModal.classList.remove('visible'));
        if (this.el.leaveGroupBtn) this.el.leaveGroupBtn.addEventListener('click', () => this._leaveGroup());
        if (this.el.acceptGroupInviteBtn) this.el.acceptGroupInviteBtn.addEventListener('click', () => this._handleGroupInvite(true));
        if (this.el.rejectGroupInviteBtn) this.el.rejectGroupInviteBtn.addEventListener('click', () => this._handleGroupInvite(false));

        // グループ通話開始ボタン
        const groupCallBtn = document.getElementById('groupCallBtn');
        if (groupCallBtn) {
            groupCallBtn.addEventListener('click', async () => {
                if (!this.currentGroupId) {
                    this.showNotification('エラー', 'グループが選択されていません', 'error');
                    return;
                }
                const gid = this.currentGroupId;
                // グループチャットモーダルを閉じる
                if (this.el.groupModal) this.el.groupModal.classList.remove('visible');
                // 既に進行中の通話があるなら参加、なければ自分がホストとして開始
                if (this.activeGroupCalls && this.activeGroupCalls.has(gid)) {
                    await this._joinActiveGroupCall(gid);
                } else {
                    await this._startGroupMeshCall(gid);
                }
            });
        }

        // グループ設定モーダル
        if (this.el.groupSettingsBtn) this.el.groupSettingsBtn.addEventListener('click', () => this._openGroupSettings());
        if (this.el.groupSettingsCloseBtn) this.el.groupSettingsCloseBtn.addEventListener('click', () => this.el.groupSettingsModal.classList.remove('visible'));
        if (this.el.groupSettingsAvatarInput) this.el.groupSettingsAvatarInput.addEventListener('change', e => this._onGroupSettingsAvatarSelected(e.target.files[0]));
        if (this.el.groupSettingsAvatarRemoveBtn) this.el.groupSettingsAvatarRemoveBtn.addEventListener('click', () => this._clearGroupSettingsAvatar());
        if (this.el.groupSettingsSaveBtn) this.el.groupSettingsSaveBtn.addEventListener('click', () => this._saveGroupSettings());

        // プロフィール画像（設定モーダル内）
        if (this.el.avatarFileInput) this.el.avatarFileInput.addEventListener('change', e => this._onAvatarFileSelected(e.target.files[0]));
        if (this.el.avatarRemoveBtn) this.el.avatarRemoveBtn.addEventListener('click', () => this._removeMyAvatar());

        // ブロック
        if (this.el.addBlockBtn) this.el.addBlockBtn.addEventListener('click', () => this._addBlock());
        if (this.el.blockSearchInput) this.el.blockSearchInput.addEventListener('keydown', e => { if (e.key === 'Enter') this._addBlock(); });

        // メッセージ取り消し用メニューのセットアップ
        this._setupRecallMenu();
    }

    doLogout() {
        const tokenToInvalidate = this.token;
        this.clearLocalSession();

        this.el.mainScreen.style.display = 'none';
        this.el.authScreen.style.display = '';
        this.el.loginName.value = '';
        this.el.loginPassword.value = '';

        this.stopHeartbeat();
        this.stopOnlineListPolling();
        FbAPI.unsubscribeSignals();
        FbAPI.unsubscribeFriends();
        FbAPI.unsubscribeGroupActiveCalls();
        this._activeCallsSubKey = null;
        // 遅延中の招待タイマーをクリア
        if (this._pendingInviteDelay) {
            for (const v of this._pendingInviteDelay.values()) {
                try { clearTimeout(v.timer); } catch (_) { }
            }
            this._pendingInviteDelay.clear();
        }
        // 通話中なら退出（ホストならFirebase上のactiveCallも消える）
        try { this._leaveMeshCall(true); } catch (_) { }
        // ローカルの進行中通話キャッシュをクリア
        if (this.activeGroupCalls) this.activeGroupCalls.clear();
        if (this._qualityInterval) {
            clearInterval(this._qualityInterval);
            this._qualityInterval = null;
        }
        // ログアウト時はメディアトラックも完全停止
        if (this.localStream) {
            try { this.localStream.getTracks().forEach(t => t.stop()); } catch (_) { }
            this.localStream = null;
            this.isMediaReady = false;
            if (this.el.localVideo) this.el.localVideo.srcObject = null;
        }
        this.cleanup().catch(() => { });
        if (tokenToInvalidate) {
            FbAPI.logout(tokenToInvalidate).catch(() => { });
        }
    }

    // =====================================================
    // PeerJS初期化
    // =====================================================
    async initializePeer() {
        this.encryptionKey = await CryptoUtil.generateKey();
        const exportedKey = await CryptoUtil.exportKey(this.encryptionKey);
        this.el.encryptionKey.value = exportedKey;

        return new Promise((resolve, reject) => {
            this.peer = new Peer({
                config: {
                    iceServers: [
                        { urls: 'stun:stun.l.google.com:19302' },
                        { urls: 'stun:stun1.google.com:19302' },
                    ],
                    iceTransportPolicy: 'all',
                    iceCandidatePoolSize: 10
                },
                secure: true,
                debug: 1
            });

            this.peer.on('open', async (id) => {
                this.el.localPeerId.value = id;
                this.updateStatus('オンライン');
                if (this.token) {
                    try { await FbAPI.heartbeat(this.token, id); } catch (_) { }
                }
                resolve(id);
            });

            this.peer.on('call', async call => {
                if (!this.currentCall) {
                    this.el.incomingCallModal.classList.remove('visible');
                    this._resetIncomingCallButtons();
                    if (this.el.callingModal.classList.contains('visible')) {
                        this.el.callingModal.classList.remove('visible');
                        const callingToEl = this.el.callingModal.querySelector('.calling-to');
                        const cancelBtn = document.getElementById('cancelCallBtn');
                        if (callingToEl) callingToEl.textContent = '呼び出し中...';
                        if (cancelBtn) cancelBtn.style.display = '';
                    }
                    call.answer(this.localStream || undefined);
                    this.handleCall(call);
                    this.el.remoteName.textContent = this.callTargetName || '相手';
                    this.el.videoGrid.style.display = '';
                    this.el.waitingState.style.display = 'none';
                    this.el.callControls.style.display = '';
                    this.showUserListSection(false);
                    this.updateStatus('通話中');
                }
            });

            this.peer.on('connection', conn => {
                if (!this.dataConnection) {
                    this.dataConnection = conn;
                    this.setupDataConnection();
                }
            });

            this.peer.on('error', err => {
                reject(err);
            });

            this.peer.on('disconnected', () => {
                this.updateStatus('再接続中...', true);
                setTimeout(() => { if (this.peer) this.peer.reconnect(); }, 3000);
            });
        });
    }

    async setupLocalStream() {
        // 既にストリームがあり、トラックがactiveなら再取得しない（カメラ・マイクの再許可を回避）
        if (this.localStream) {
            const tracks = this.localStream.getTracks();
            const allActive = tracks.length > 0 && tracks.every(t => t.readyState === 'live');
            if (allActive) {
                // トラックを状態に合わせて有効化（無効化されていた場合に備えて）
                this.localStream.getAudioTracks().forEach(t => t.enabled = this.isAudioEnabled !== false);
                this.localStream.getVideoTracks().forEach(t => t.enabled = this.isVideoEnabled === true);
                if (this.el.localVideo) {
                    if (this.el.localVideo.srcObject !== this.localStream) {
                        this.el.localVideo.srcObject = this.localStream;
                    }
                    this.el.localVideo.style.display = '';
                }
                this.isMediaReady = true;
                // UIを最新の state に同期（ボタン表示崩れ対策）
                this._syncMediaButtonsUI();
                this._updateLocalAvatarOverlay();
                return;
            }
        }
        this.updateStatus('カメラ/マイク準備中...');
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
            this.el.localVideo.srcObject = this.localStream;
            // カメラはOFFスタート（要件1）
            this.localStream.getVideoTracks().forEach(t => t.enabled = this.isVideoEnabled === true);
            this.localStream.getAudioTracks().forEach(t => t.enabled = this.isAudioEnabled !== false);
            this.isMediaReady = true;
        } catch (e) {
            console.warn('カメラ/マイクの許可が得られませんでした:', e);
            this.localStream = null;
            this.isMediaReady = false;
            if (this.el.localVideo) this.el.localVideo.style.display = 'none';
        }
        // UIを最新の state に同期
        this._syncMediaButtonsUI();
        this._updateLocalAvatarOverlay();
        this.updateStatus('オンライン');
    }

    // マイク/カメラボタンの表示を現在の state に強制同期する（再通話時の表示崩れを防ぐ）
    _syncMediaButtonsUI() {
        // メッシュ通話中ならメッシュの状態を見る
        const inMesh = this._meshIsInCall && this._meshIsInCall();
        const micOn = inMesh ? this.meshMicOn : this.isAudioEnabled;
        const camOn = inMesh ? this.meshCamOn : this.isVideoEnabled;
        const sharing = inMesh ? this.meshIsScreenSharing : this.isScreenSharing;

        if (this.el.toggleMicButton) {
            this.el.toggleMicButton.classList.toggle('active', !micOn);
            const icon = this.el.toggleMicButton.querySelector('i');
            if (icon) icon.className = micOn ? 'fas fa-microphone' : 'fas fa-microphone-slash';
        }
        if (this.el.toggleVideoButton) {
            this.el.toggleVideoButton.classList.toggle('active', !camOn);
            const icon = this.el.toggleVideoButton.querySelector('i');
            if (icon) icon.className = camOn ? 'fas fa-video' : 'fas fa-video-slash';
        }
        if (this.el.screenShareButton) {
            this.el.screenShareButton.classList.toggle('sharing', !!sharing);
            const icon = this.el.screenShareButton.querySelector('i');
            if (icon) icon.className = sharing ? 'fas fa-stop' : 'fas fa-desktop';
            this.el.screenShareButton.title = sharing ? '画面共有を停止' : '画面共有';
        }
    }

    // =====================================================
    // オンラインユーザーリスト
    // =====================================================
    async refreshOnlineList() {
        const icon = this.el.refreshListBtn.querySelector('i');
        icon.classList.add('fa-spin');

        try {
            const res = await FbAPI.onlineList(this.token);
            if (res.ok) {
                this._lastOnlineUsers = res.users || [];
                this.renderUserList(res.users);
            } else if (res.error === 'セッションが無効です') {
                this.doLogout();
            }
        } catch (e) {
            console.warn('リスト更新失敗:', e);
        }

        icon.classList.remove('fa-spin');
    }

    // フレンドリストが変わったとき、現在のオンラインリストを再描画する
    _rerenderOnlineListIfPossible() {
        if (this._lastOnlineUsers && Array.isArray(this._lastOnlineUsers)) {
            this.renderUserList(this._lastOnlineUsers);
        }
    }

    renderUserList(users) {
        const list = this.el.userList;
        list.innerHTML = '';

        if (!users || users.length === 0) {
            list.innerHTML = `
                <div class="user-list-empty">
                    <i class="fas fa-user-slash"></i>
                    <p>オンラインのユーザーがいません</p>
                </div>`;
            return;
        }

        // フレンドを上に、非フレンドを下に並び替え（それぞれの中は名前順）
        const sortedUsers = [...users].sort((a, b) => {
            const aIsFriend = this.friendNames.has(a.name) ? 1 : 0;
            const bIsFriend = this.friendNames.has(b.name) ? 1 : 0;
            if (aIsFriend !== bIsFriend) return bIsFriend - aIsFriend; // フレンドが先
            return a.name.localeCompare(b.name, 'ja');
        });

        sortedUsers.forEach(user => {
            const isFriend = this.friendNames.has(user.name);
            const item = document.createElement('div');
            item.className = 'user-item' + (isFriend ? ' is-friend' : '');
            item.dataset.name = user.name;
            item.dataset.peerId = user.peer_id;
            const avUrl = this.avatarCache[user.name];
            const avClass = avUrl ? 'user-avatar has-image' : 'user-avatar';
            const avStyle = avUrl ? `background-image:url('${avUrl}')` : '';
            const initial = avUrl ? '' : user.name.charAt(0).toUpperCase();
            // フレンドアイコン（小さなハート） + 通話ボタンはフレンドのみ
            const friendMark = isFriend
                ? `<span class="user-friend-mark" title="フレンド"><i class="fas fa-user-check"></i></span>`
                : '';
            const callBtnHtml = isFriend
                ? `<button class="call-user-btn" data-action="call" title="通話"><i class="fas fa-phone"></i></button>`
                : '';
            item.innerHTML = `
                <div class="user-item-info">
                    <div class="${avClass}" data-uname="${this.escapeHtml(user.name)}" style="${avStyle}">${initial}</div>
                    <span class="user-item-name">${this.escapeHtml(user.name)}</span>
                    ${friendMark}
                    <span class="user-online-dot"></span>
                </div>
                ${callBtnHtml}`;
            // フレンドの場合のみ通話ボタンにクリックハンドラ
            if (isFriend) {
                const btn = item.querySelector('.call-user-btn');
                if (btn) {
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        this.startOutgoingCall(user.name, user.peer_id);
                    });
                }
            }
            list.appendChild(item);
        });

        // まだキャッシュにないユーザーのアバターをバックグラウンドで取得
        this._fetchAvatarsFor(sortedUsers.map(u => u.name)).then(() => this._refreshAvatarsInDom());
    }

    escapeHtml(str) {
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // =====================================================
    // フレンド機能
    // =====================================================
    async refreshFriendList() {
        if (!this.token) return;
        try {
            const res = await FbAPI.getFriends(this.token);
            if (!res.ok) return;
            this._applyFriendData(res);
        } catch (e) {
            console.warn('フレンドリスト取得失敗:', e);
        }
    }

    // 取得した friends データをキャッシュ・バッジ・UIに反映する共通処理
    _applyFriendData(res) {
        const prevFriends = this.friendNames ? new Set(this.friendNames) : new Set();
        this.friendNames = new Set([
            ...(res.friends || []),
            ...(res.incoming || []).map(r => r.from),
        ]);
        const incomingCount = (res.incoming || []).length;
        this._updateFriendBadge(incomingCount);
        this._cachedFriendData = res;
        // フレンドセットに変更があればオンラインリストの並び・通話ボタン表示を更新
        const changed = prevFriends.size !== this.friendNames.size ||
            [...this.friendNames].some(n => !prevFriends.has(n)) ||
            [...prevFriends].some(n => !this.friendNames.has(n));
        if (changed) this._rerenderOnlineListIfPossible();
        // フレンドモーダルが開いていれば即時再描画
        if (this.el.friendModal && this.el.friendModal.classList.contains('visible')) {
            this._renderFriendModal();
        }
    }

    // friends ノードをリアルタイム購読する
    // 相手が名前を変更した場合や、別端末でフレンド操作が行われた場合に
    // こちら側の friendNames キャッシュとUIを自動更新する
    subscribeFriendStream() {
        if (!this.myName) return;
        FbAPI.subscribeFriends(() => this.myName, (res) => {
            if (res?.ok) this._applyFriendData(res);
        });
    }

    _updateFriendBadge(count) {
        const badge = this.el.friendRequestBadge;
        const tabBadge = this.el.requestTabBadge;
        if (!badge) return;
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = '';
            if (tabBadge) { tabBadge.textContent = count; tabBadge.style.display = ''; }
        } else {
            badge.style.display = 'none';
            if (tabBadge) tabBadge.style.display = 'none';
        }
    }

    openFriendModal() {
        this.el.friendModal.classList.add('visible');
        this._renderFriendModal();

        if (!this._cachedFriendData) {
            FbAPI.getFriends(this.token).then(res => {
                if (res?.ok) {
                    this.friendNames = new Set([
                        ...(res.friends || []),
                        ...(res.incoming || []).map(r => r.from),
                    ]);
                    this._updateFriendBadge((res.incoming || []).length);
                    this._cachedFriendData = res;
                    if (this.el.friendModal.classList.contains('visible')) {
                        this._renderFriendModal();
                    }
                }
            }).catch(() => { });
        }
    }

    _renderFriendModal() {
        if (!this._cachedFriendData) {
            const loading = '<div class="friend-empty"><i class="fas fa-spinner fa-spin"></i><p>読み込み中...</p></div>';
            this.el.friendList.innerHTML = loading;
            this.el.incomingRequests.innerHTML = loading;
            this.el.outgoingRequests.innerHTML = loading;
            return;
        }

        const data = this._cachedFriendData;
        const friends = data.friends || [];
        const incoming = data.incoming || [];
        const outgoing = data.outgoing || [];

        const fl = this.el.friendList;
        if (friends.length === 0) {
            fl.innerHTML = '<div class="friend-empty"><i class="fas fa-user-slash"></i><p>フレンドがいません</p></div>';
        } else {
            fl.innerHTML = friends.map(name => {
                const avUrl = this.avatarCache[name];
                const avClass = avUrl ? 'friend-item-avatar has-image' : 'friend-item-avatar';
                const avStyle = avUrl ? `background-image:url('${avUrl}')` : '';
                const initial = avUrl ? '' : this.escapeHtml(name.charAt(0).toUpperCase());
                return `
                <div class="friend-item">
                    <div class="${avClass}" data-uname="${this.escapeHtml(name)}" style="${avStyle}">${initial}</div>
                    <span class="friend-item-name">${this.escapeHtml(name)}</span>
                    <div class="friend-item-actions">
                        <button class="friend-dm-btn" data-name="${this.escapeHtml(name)}">
                            <i class="fas fa-comment-dots"></i> DM
                        </button>
                        <button class="friend-remove-btn" data-name="${this.escapeHtml(name)}">
                            <i class="fas fa-user-minus"></i> 削除
                        </button>
                    </div>
                </div>`;
            }).join('');
            fl.querySelectorAll('.friend-dm-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    this.el.friendModal.classList.remove('visible');
                    this.el.dmModal.classList.add('visible');
                    this._openDmChat(btn.dataset.name);
                });
            });
            fl.querySelectorAll('.friend-remove-btn').forEach(btn => {
                btn.addEventListener('click', () => this.removeFriend(btn.dataset.name, btn));
            });
        }

        const ir = this.el.incomingRequests;
        if (incoming.length === 0) {
            ir.innerHTML = '<div class="friend-empty"><i class="fas fa-inbox"></i><p>受信した申請はありません</p></div>';
        } else {
            ir.innerHTML = incoming.map(r => {
                const avUrl = this.avatarCache[r.from];
                const avClass = avUrl ? 'friend-item-avatar has-image' : 'friend-item-avatar';
                const avStyle = avUrl ? `background-image:url('${avUrl}')` : '';
                const initial = avUrl ? '' : this.escapeHtml(r.from.charAt(0).toUpperCase());
                return `
                <div class="friend-item">
                    <div class="${avClass}" data-uname="${this.escapeHtml(r.from)}" style="${avStyle}">${initial}</div>
                    <span class="friend-item-name">${this.escapeHtml(r.from)}</span>
                    <div class="friend-item-actions">
                        <button class="friend-accept-btn" data-name="${this.escapeHtml(r.from)}">
                            <i class="fas fa-check"></i> 承認
                        </button>
                        <button class="friend-reject-btn" data-name="${this.escapeHtml(r.from)}">
                            <i class="fas fa-times"></i> 拒否
                        </button>
                    </div>
                </div>`;
            }).join('');
            ir.querySelectorAll('.friend-accept-btn').forEach(btn => {
                btn.addEventListener('click', () => this.acceptFriendRequest(btn.dataset.name, btn));
            });
            ir.querySelectorAll('.friend-reject-btn').forEach(btn => {
                btn.addEventListener('click', () => this.rejectFriendRequest(btn.dataset.name, btn));
            });
        }

        const or = this.el.outgoingRequests;
        if (outgoing.length === 0) {
            or.innerHTML = '<div class="friend-empty"><i class="fas fa-paper-plane"></i><p>送信した申請はありません</p></div>';
        } else {
            or.innerHTML = outgoing.map(r => {
                const avUrl = this.avatarCache[r.to];
                const avClass = avUrl ? 'friend-item-avatar has-image' : 'friend-item-avatar';
                const avStyle = avUrl ? `background-image:url('${avUrl}')` : '';
                const initial = avUrl ? '' : this.escapeHtml(r.to.charAt(0).toUpperCase());
                return `
                <div class="friend-item">
                    <div class="${avClass}" data-uname="${this.escapeHtml(r.to)}" style="${avStyle}">${initial}</div>
                    <span class="friend-item-name">${this.escapeHtml(r.to)}</span>
                    <div class="friend-item-actions">
                        <span style="font-size:0.8rem;color:var(--text-secondary)">承認待ち</span>
                    </div>
                </div>`;
            }).join('');
        }

        // キャッシュに無い名前のアバターをバックグラウンド取得
        const allNames = [
            ...friends,
            ...incoming.map(r => r.from),
            ...outgoing.map(r => r.to),
        ];
        this._fetchAvatarsFor(allNames).then(() => this._refreshAvatarsInDom());
    }

    async sendFriendRequest() {
        const name = this.el.friendSearchInput?.value.trim();
        this.el.friendAddError.textContent = '';
        if (!name) { this.el.friendAddError.textContent = '名前を入力してください'; return; }
        if (name === this.myName) { this.el.friendAddError.textContent = '自分自身には申請できません'; return; }

        const btn = this.el.sendFriendRequestBtn;
        const origHTML = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 申請中...';

        try {
            const res = await FbAPI.sendFriendRequest(this.token, name);
            if (res.ok) {
                this.el.friendSearchInput.value = '';
                try { await FbAPI.sendSignal(this.token, name, 'friend_request', ''); } catch (_) { }
                await this.refreshFriendList();
                this._renderFriendModal();
                this.showNotification('フレンド', `${name} にフレンド申請を送りました`, 'success');
            } else {
                this.el.friendAddError.textContent = res.error || '申請に失敗しました';
            }
        } catch (e) {
            this.el.friendAddError.textContent = 'サーバーへの接続に失敗しました';
        }

        btn.disabled = false;
        btn.innerHTML = origHTML;
    }

    async acceptFriendRequest(fromName, btnEl) {
        if (btnEl) { btnEl.disabled = true; btnEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 承認中...'; }
        try {
            const res = await FbAPI.acceptFriend(this.token, fromName);
            if (res.ok) {
                try { await FbAPI.sendSignal(this.token, fromName, 'friend_accept', ''); } catch (_) { }
                await this.refreshFriendList();
                this._renderFriendModal();
                this.showNotification('フレンド', `${fromName} をフレンドに追加しました`, 'success');
            } else {
                this.showNotification('エラー', res.error || '承認に失敗しました', 'error');
                if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = '<i class="fas fa-check"></i> 承認'; }
            }
        } catch (e) {
            this.showNotification('エラー', 'サーバーへの接続に失敗しました', 'error');
            if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = '<i class="fas fa-check"></i> 承認'; }
        }
    }

    async rejectFriendRequest(fromName, btnEl) {
        if (btnEl) { btnEl.disabled = true; btnEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 拒否中...'; }
        try {
            const res = await FbAPI.rejectFriend(this.token, fromName);
            if (res.ok) {
                try { await FbAPI.sendSignal(this.token, fromName, 'friend_reject', ''); } catch (_) { }
                await this.refreshFriendList();
                this._renderFriendModal();
            } else {
                this.showNotification('エラー', res.error || '拒否に失敗しました', 'error');
                if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = '<i class="fas fa-times"></i> 拒否'; }
            }
        } catch (e) {
            this.showNotification('エラー', 'サーバーへの接続に失敗しました', 'error');
            if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = '<i class="fas fa-times"></i> 拒否'; }
        }
    }

    async removeFriend(targetName, btnEl) {
        if (btnEl) { btnEl.disabled = true; btnEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 削除中...'; }
        try {
            const res = await FbAPI.removeFriend(this.token, targetName);
            if (res.ok) {
                this.friendNames.delete(targetName);
                await this.refreshFriendList();
                this._renderFriendModal();
            } else {
                this.showNotification('エラー', res.error || '削除に失敗しました', 'error');
                if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = '<i class="fas fa-user-minus"></i> 削除'; }
            }
        } catch (e) {
            this.showNotification('エラー', 'サーバーへの接続に失敗しました', 'error');
            if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = '<i class="fas fa-user-minus"></i> 削除'; }
        }
    }

    showIncomingFriendRequest(signal) {
        if (this.pendingFriendSignal) return;
        this.pendingFriendSignal = signal;
        if (this.el.acceptFriendRequestBtn) {
            this.el.acceptFriendRequestBtn.disabled = false;
            this.el.acceptFriendRequestBtn.innerHTML = '<i class="fas fa-check"></i> 承認する';
        }
        if (this.el.rejectFriendRequestBtn) {
            this.el.rejectFriendRequestBtn.disabled = false;
            this.el.rejectFriendRequestBtn.innerHTML = '<i class="fas fa-times"></i> 拒否する';
        }
        if (this.el.friendRequestFromName) this.el.friendRequestFromName.textContent = signal.from;
        this.el.incomingFriendRequestModal.classList.add('visible');
    }

    async handleIncomingFriendRequest(accept) {
        if (this._friendRequestHandling) return;
        this._friendRequestHandling = true;

        const signal = this.pendingFriendSignal;
        if (!signal) { this._friendRequestHandling = false; return; }

        const acceptBtn = this.el.acceptFriendRequestBtn;
        const rejectBtn = this.el.rejectFriendRequestBtn;
        if (acceptBtn) acceptBtn.disabled = true;
        if (rejectBtn) rejectBtn.disabled = true;
        if (accept && acceptBtn) acceptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 承認中...';
        if (!accept && rejectBtn) rejectBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 拒否中...';

        try {
            if (accept) {
                const res = await FbAPI.acceptFriend(this.token, signal.from);
                if (res.ok) {
                    try { await FbAPI.sendSignal(this.token, signal.from, 'friend_accept', ''); } catch (_) { }
                    this.pendingFriendSignal = null;
                    this.el.incomingFriendRequestModal.classList.remove('visible');
                    await this.refreshFriendList();
                    this._renderFriendModal();
                    this.showNotification('フレンド', `${signal.from} をフレンドに追加しました`, 'success');
                } else {
                    this.showNotification('エラー', res.error || '承認に失敗しました', 'error');
                    if (acceptBtn) { acceptBtn.disabled = false; acceptBtn.innerHTML = '<i class="fas fa-check"></i> 承認する'; }
                    if (rejectBtn) { rejectBtn.disabled = false; }
                    this._friendRequestHandling = false;
                    return;
                }
            } else {
                const res = await FbAPI.rejectFriend(this.token, signal.from);
                if (res.ok) {
                    try { await FbAPI.sendSignal(this.token, signal.from, 'friend_reject', ''); } catch (_) { }
                }
                this.pendingFriendSignal = null;
                this.el.incomingFriendRequestModal.classList.remove('visible');
                await this.refreshFriendList();
                this._renderFriendModal();
            }
        } catch (e) {
            this.showNotification('エラー', 'サーバーへの接続に失敗しました', 'error');
            if (acceptBtn) { acceptBtn.disabled = false; acceptBtn.innerHTML = '<i class="fas fa-check"></i> 承認する'; }
            if (rejectBtn) { rejectBtn.disabled = false; rejectBtn.innerHTML = '<i class="fas fa-times"></i> 拒否する'; }
            this._friendRequestHandling = false;
            return;
        }

        this._friendRequestHandling = false;
    }

    // =====================================================
    // 設定
    // =====================================================
    openSettingsModal() {
        if (this.el.settingsAutoLogin) this.el.settingsAutoLogin.checked = this.autoLoginEnabled;
        // 管理者セクション: 本名が "管理者" の場合のみ表示
        const adminSection = document.getElementById('settingsAdminSection');
        if (adminSection) {
            adminSection.style.display = (this.myName === '管理者') ? '' : 'none';
        }
        // プロフィール画像プレビューを更新
        this._updateAvatarPreview();
        if (this.el.avatarError) this.el.avatarError.textContent = '';
        this.el.settingsModal.classList.add('visible');
    }

    saveSettings() {
        const autoLogin = this.el.settingsAutoLogin?.checked || false;

        this.autoLoginEnabled = autoLogin;
        localStorage.setItem('svc_autologin', autoLogin ? '1' : '0');

        localStorage.setItem('svc_settings', JSON.stringify(this.settings));

        if (this.el.autoLoginCheck) this.el.autoLoginCheck.checked = autoLogin;

        this.el.settingsModal.classList.remove('visible');
        this.showNotification('設定', '設定を保存しました', 'success');
    }

    async doChangeName() {
        const newName = this.el.settingsNewName?.value.trim();
        const password = this.el.settingsNameCurrentPw?.value.trim();
        if (this.el.settingsNameError) this.el.settingsNameError.textContent = '';

        if (!newName) { this.el.settingsNameError.textContent = '新しい本名を入力してください'; return; }
        if (!password) { this.el.settingsNameError.textContent = '現在のパスワードを入力してください'; return; }
        if (newName === this.myName) { this.el.settingsNameError.textContent = '現在と同じ名前です'; return; }

        const btn = this.el.settingsChangeNameBtn;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 変更中...';

        try {
            const res = await FbAPI.changeName(this.token, newName, password);
            if (res.ok) {
                const oldName = this.myName;
                this.myName = newName;
                localStorage.setItem('svc_name', newName);
                this.el.headerUserName.textContent = newName;
                this.el.localName.textContent = newName;
                if (this.el.settingsNewName) this.el.settingsNewName.value = '';
                if (this.el.settingsNameCurrentPw) this.el.settingsNameCurrentPw.value = '';

                // アバターキャッシュのキーを新しい名前に引き継ぐ（Firebase 側の profiles は
                // サーバー changeName で引っ越し済みなので再アップロードは不要）
                if (this.avatarCache[oldName]) {
                    this.avatarCache[newName] = this.avatarCache[oldName];
                    delete this.avatarCache[oldName];
                    this._saveAvatarCache();
                }
                this._updateAvatarPreview();

                // フレンドキャッシュを再取得（自分の名前変更後、表示用キャッシュをリフレッシュ）
                try {
                    const fr = await FbAPI.getFriends(this.token);
                    if (fr?.ok) this._applyFriendData(fr);
                } catch (_) { }

                // シグナル購読・フレンド購読を新しい名前で再開
                this.subscribeSignalStream();
                this.subscribeFriendStream();
                FbAPI.setupPresenceOnDisconnect(this.myName);

                this.showNotification('設定', `本名を「${newName}」に変更しました`, 'success');
            } else {
                this.el.settingsNameError.textContent = res.error || '名前の変更に失敗しました';
            }
        } catch (e) {
            this.el.settingsNameError.textContent = 'サーバーへの接続に失敗しました';
        }

        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-check"></i> 変更する';
    }

    async doChangePassword() {
        const currentPw = this.el.settingsCurrentPw?.value.trim();
        const newPw = this.el.settingsNewPw?.value.trim();
        const newPwConfirm = this.el.settingsNewPwConfirm?.value.trim();
        if (this.el.settingsPwError) this.el.settingsPwError.textContent = '';

        if (!currentPw) { this.el.settingsPwError.textContent = '現在のパスワードを入力してください'; return; }
        if (!newPw || newPw.length < 4) { this.el.settingsPwError.textContent = '新しいパスワードは4文字以上で入力してください'; return; }
        if (!/^[a-zA-Z0-9]+$/.test(newPw)) { this.el.settingsPwError.textContent = '半角英数字のみ使用できます'; return; }
        if (newPw !== newPwConfirm) { this.el.settingsPwError.textContent = 'パスワードが一致しません'; return; }
        if (newPw === currentPw) { this.el.settingsPwError.textContent = '現在と同じパスワードです'; return; }

        const btn = this.el.settingsChangePwBtn;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 変更中...';

        try {
            const res = await FbAPI.changePassword(this.token, currentPw, newPw);
            if (res.ok) {
                this.el.settingsCurrentPw.value = '';
                this.el.settingsNewPw.value = '';
                this.el.settingsNewPwConfirm.value = '';
                this.showNotification('設定', 'パスワードを変更しました', 'success');
            } else {
                this.el.settingsPwError.textContent = res.error || 'パスワードの変更に失敗しました';
            }
        } catch (e) {
            this.el.settingsPwError.textContent = 'サーバーへの接続に失敗しました';
        }

        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-check"></i> 変更する';
    }

    // =====================================================
    // 管理者: 全ユーザーへ一斉DM
    // =====================================================
    async doAdminBroadcast() {
        if (this.myName !== '管理者') return;
        const textarea = document.getElementById('adminBroadcastText');
        const errorEl = document.getElementById('adminBroadcastError');
        const btn = document.getElementById('adminBroadcastBtn');
        if (errorEl) errorEl.textContent = '';

        const text = textarea?.value.trim();
        if (!text) {
            if (errorEl) errorEl.textContent = 'メッセージを入力してください';
            return;
        }
        if (text.length > 500) {
            if (errorEl) errorEl.textContent = '500文字以内で入力してください';
            return;
        }

        if (!confirm(`このメッセージを全ユーザーに「管理者からのお知らせ」として送信します。よろしいですか？\n\n${text.slice(0, 80)}${text.length > 80 ? '…' : ''}`)) {
            return;
        }

        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 送信中...';

        try {
            const res = await FbAPI.getAllAccounts(this.token);
            if (!res.ok) {
                if (errorEl) errorEl.textContent = res.error || 'ユーザー一覧の取得に失敗しました';
                return;
            }
            const recipients = (res.names || []).filter(n => n && n !== this.myName);
            if (recipients.length === 0) {
                if (errorEl) errorEl.textContent = '送信先がいません';
                return;
            }

            const ts = Date.now();
            let success = 0;
            let failed = 0;

            // 各ユーザーへ admin_broadcast 型のDMを送信
            // 自分のローカルにも各会話に記録（送信記録として）
            for (const target of recipients) {
                const msg = {
                    msgId: this._genMsgId(),
                    from: this.myName,
                    content: text,
                    ts: ts,
                    type: 'admin_broadcast'
                };
                // ローカルDB保存（送信履歴）
                const key = this._dmKey(target);
                this._addMessage(key, msg);
                // 送信
                try {
                    const sres = await FbAPI.sendSignal(this.token, target, 'dm', encodeURIComponent(JSON.stringify(msg)));
                    if (sres?.ok) success++; else failed++;
                } catch (_) {
                    failed++;
                }
            }

            textarea.value = '';
            this.showNotification(
                '一斉送信完了',
                `${success}人に送信しました${failed > 0 ? `（失敗: ${failed}人）` : ''}`,
                failed > 0 ? 'warning' : 'success'
            );

            // 開いていればDM会話一覧を更新
            if (this.el.dmModal?.classList.contains('visible')) {
                this._renderDmConversationList();
            }
        } catch (e) {
            console.error(e);
            if (errorEl) errorEl.textContent = '送信に失敗しました';
        }

        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-paper-plane"></i> 全員に送信';
    }

    // =====================================================
    // ハートビート（5秒ごと）
    // =====================================================
    startHeartbeat() {
        this.stopHeartbeat();
        this.heartbeatInterval = setInterval(async () => {
            if (!this.token) return;
            const peerId = this.peer?.id || '';
            try {
                const res = await FbAPI.heartbeat(this.token, peerId);
                if (!res.ok) this.doLogout();
            } catch (_) { }
        }, 5000);
    }

    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    // =====================================================
    // オンラインリスト定期更新（4秒ごと）
    // =====================================================
    startOnlineListPolling() {
        this.stopOnlineListPolling();
        this.onlineListInterval = setInterval(async () => {
            // 通話中はリスト更新不要
            if (this.currentCall) return;
            await this.refreshOnlineList();
        }, 4000);
    }

    stopOnlineListPolling() {
        if (this.onlineListInterval) {
            clearInterval(this.onlineListInterval);
            this.onlineListInterval = null;
        }
    }

    // =====================================================
    // シグナルのリアルタイム購読
    // =====================================================
    subscribeSignalStream() {
        if (!this.myName) return;
        // 遅延中の mesh_invite を一時保持するマップ (送信者名 -> { timer, signal })
        // 招待を受け取ってもすぐにモーダル表示せず、短時間待ってから処理する。
        // その間に同じ送信者から cancel/reject が来たら破棄する。
        // これにより、オフライン中に蓄積した invite + cancel のペアや、
        // 招待直後に発信側が通話を終わらせたケースで、モーダルが一瞬出る問題を防ぐ。
        if (!this._pendingInviteDelay) this._pendingInviteDelay = new Map();

        FbAPI.subscribeSignals(this.myName, async (signal) => {
            // 処理済みシグナルは無視
            if (this._processedSignalIds.has(signal.id)) {
                await FbAPI.ackSignal(this.token, signal.id, this.myName);
                return;
            }
            this._processedSignalIds.add(signal.id);

            // mesh_invite は遅延処理する
            if (signal.type === 'mesh_invite') {
                // 既に同じ送信者から遅延中の invite があれば、新しい方で上書き
                const existing = this._pendingInviteDelay.get(signal.from);
                if (existing) {
                    clearTimeout(existing.timer);
                    // 古い招待は ack 済み扱いにする
                    if (existing.signal && existing.signal.id !== signal.id) {
                        FbAPI.ackSignal(this.token, existing.signal.id, this.myName).catch(() => { });
                    }
                }
                const timer = setTimeout(async () => {
                    this._pendingInviteDelay.delete(signal.from);
                    try {
                        await this.handleSignal(signal);
                    } catch (e) {
                        console.warn('handleSignalエラー:', e);
                    }
                    await FbAPI.ackSignal(this.token, signal.id, this.myName);
                }, 700); // 700ms 遅延（同時に届いた cancel を拾うのに十分な時間）
                this._pendingInviteDelay.set(signal.from, { timer, signal });
            } else if (signal.type === 'mesh_invite_cancel' || signal.type === 'mesh_invite_reject') {
                // 遅延中の invite があれば破棄
                const pending = this._pendingInviteDelay.get(signal.from);
                if (pending) {
                    clearTimeout(pending.timer);
                    this._pendingInviteDelay.delete(signal.from);
                    // 破棄された invite は ack
                    FbAPI.ackSignal(this.token, pending.signal.id, this.myName).catch(() => { });
                    // この cancel/reject 自体も処理不要（モーダルが出ていないため）。ackだけ
                    await FbAPI.ackSignal(this.token, signal.id, this.myName);
                } else {
                    // 通常通り処理
                    try {
                        await this.handleSignal(signal);
                    } catch (e) {
                        console.warn('handleSignalエラー:', e);
                    }
                    await FbAPI.ackSignal(this.token, signal.id, this.myName);
                }
            } else {
                try {
                    await this.handleSignal(signal);
                } catch (e) {
                    console.warn('handleSignalエラー:', e);
                }
                // シグナル処理後は削除（ack相当）
                await FbAPI.ackSignal(this.token, signal.id, this.myName);
            }

            if (this._processedSignalIds.size > 200) {
                const it = this._processedSignalIds.values();
                this._processedSignalIds.delete(it.next().value);
            }
        });
    }

    async handleSignal(signal) {
        console.log('[シグナル受信]', signal);
        switch (signal.type) {
            // ============ メッシュ通話シグナル ============
            case 'mesh_invite':
                this._onMeshInviteReceived(signal);
                break;

            case 'mesh_invite_accept':
                this._onMeshInviteAccepted(signal);
                break;

            case 'mesh_invite_reject':
                this._onMeshInviteRejected(signal);
                break;

            case 'mesh_invite_cancel':
                this._onMeshInviteCanceled(signal);
                break;

            case 'group_call_notify':
                this._onGroupCallNotified(signal);
                break;

            case 'group_call_end':
                this._onGroupCallEnded(signal);
                break;

            case 'friend_request':
                this.showIncomingFriendRequest(signal);
                await this.refreshFriendList();
                if (this.el.friendModal?.classList.contains('visible')) this._renderFriendModal();
                break;

            case 'friend_accept':
                this.friendNames.add(signal.from);
                this.showNotification('フレンド', `${signal.from} がフレンド申請を承認しました`, 'success');
                await this.refreshFriendList();
                if (this.el.friendModal?.classList.contains('visible')) this._renderFriendModal();
                this._rerenderOnlineListIfPossible();
                break;

            case 'friend_reject':
                this.showNotification('フレンド', `${signal.from} にフレンド申請を拒否されました`, 'warning');
                await this.refreshFriendList();
                if (this.el.friendModal?.classList.contains('visible')) this._renderFriendModal();
                break;

            case 'dm':
                // DMはブロック判定のみで受信
                if (this.blockedUsers.has(signal.from)) break;
                try {
                    const dmData = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._receiveDmMessage(signal.from, dmData);
                } catch (_) { }
                break;

            case 'group_invite':
                if (this.blockedUsers.has(signal.from)) break;
                try {
                    const inv = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._showGroupInvite(signal.from, inv);
                } catch (_) { }
                break;

            case 'group_msg':
                if (this.blockedUsers.has(signal.from)) break;
                try {
                    const gData = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._receiveGroupMessage(gData.groupId, signal.from, gData);
                } catch (_) { }
                break;

            case 'group_member_left':
                try {
                    const leftData = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._handleMemberLeft(leftData.groupId, signal.from);
                } catch (_) { }
                break;

            case 'read_receipt':
                // 既読通知: { convType: 'dm' | 'group', convKey, msgIds: [...] }
                if (this.blockedUsers.has(signal.from)) break;
                try {
                    const rr = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._applyReadReceipt(signal.from, rr);
                } catch (_) { }
                break;

            case 'msg_recall':
                // メッセージ取り消し通知: { convType: 'dm' | 'group', msgId, convKey?, groupId? }
                if (this.blockedUsers.has(signal.from)) break;
                try {
                    const rcPayload = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._applyRemoteRecall(signal.from, rcPayload);
                } catch (_) { }
                break;

            case 'name_changed':
                // 相手が名前を変えた: ローカルDM履歴のキーを旧名→新名にマージする
                try {
                    const nc = JSON.parse(decodeURIComponent(signal.signal_data));
                    if (nc && nc.oldName && nc.newName) {
                        this._handlePartnerNameChanged(nc.oldName, nc.newName);
                    }
                } catch (_) { }
                break;
        }
    }

    // =====================================================
    // 発信（メッシュ通話にリダイレクト）
    // =====================================================
    async startOutgoingCall(targetName, targetPeerId) {
        // targetPeerId は既存呼び出し互換のため受け取るが使用しない
        // メッシュ通話では PeerJSのID = meshcall-{ホスト本名}-{...} で接続するため、peerIdは不要
        return this._startOneToOneMeshCall(targetName);
    }

    async cancelOutgoingCall() {
        return this._cancelMeshOutgoingCall();
    }

    // initiateWebRTCCall, showIncomingCall は廃止（メッシュ系に統合）

    // 既存のUIイベント（acceptCallBtn / rejectCallBtn）から呼ばれるため、メソッド名は残し中身をメッシュ版へ
    async acceptIncomingCall() {
        return this._acceptMeshIncomingCall();
    }

    async rejectIncomingCall() {
        return this._rejectMeshIncomingCall();
    }

    _resetIncomingCallButtons() {
        this._incomingCallHandled = false;
        if (this.el.acceptCallBtn) {
            this.el.acceptCallBtn.classList.remove('processing');
            this.el.acceptCallBtn.innerHTML = '<i class="fas fa-phone"></i> 応答する';
            this.el.acceptCallBtn.disabled = false;
        }
        if (this.el.rejectCallBtn) {
            this.el.rejectCallBtn.classList.remove('processing');
            this.el.rejectCallBtn.innerHTML = '<i class="fas fa-phone-slash"></i> 拒否する';
            this.el.rejectCallBtn.disabled = false;
        }
    }

    // =====================================================
    // 旧WebRTC通話処理は削除（メッシュ通話に統合）
    // 既存コードから呼ばれているメソッドはno-opまたはリダイレクト
    // =====================================================
    handleCall() { /* 旧1対1WebRTC用。廃止 */ }
    setupDataConnection() { /* 旧1対1WebRTC用。廃止 */ }
    handleRemoteDisconnect() { /* 旧1対1WebRTC用。廃止 */ }
    async sendDisconnectSignal() { /* 旧1対1WebRTC用。廃止 */ }
    _attachRemoteVideoTrackWatcher() { /* 旧1対1WebRTC用。廃止 */ }

    // 既存のdisconnectButtonから呼ばれる。メッシュ通話の退出として動作。
    async disconnect() {
        if (this.isDisconnecting) return;
        this.isDisconnecting = true;

        try {
            await this._leaveMeshCall(true);
        } catch (e) {
            console.warn('[disconnect] _leaveMeshCall失敗:', e);
        }

        if (this._qualityInterval) {
            clearInterval(this._qualityInterval);
            this._qualityInterval = null;
        }
        if (this.audioContext) {
            try { this.audioContext.close(); } catch (_) { }
            this.audioContext = null;
            this.gainNode = null;
            this.preGainNode = null;
            this.compressorNode = null;
            this.makeUpGainNode = null;
            this.audioSource = null;
        }
        if (this.el.remoteVideo) this.el.remoteVideo.muted = false;
        this.isVolumeControlVisible = false;
        if (this.el.volumeSliderContainer) this.el.volumeSliderContainer.classList.remove('visible');
        this.currentVolume = 100;
        if (this.el.volumeSlider) this.el.volumeSlider.value = 100;
        if (this._refreshVolumeUI) this._refreshVolumeUI(100);

        this.disconnectedBySelf = false;
        this.isDisconnecting = false;
        this.callTargetName = null;

        // 旧フラグも同期リセット
        this.isVideoEnabled = false;
        this.isAudioEnabled = true;
        this.isScreenSharing = false;
        this.savedCameraTrack = null;
        this.remoteCameraOff = false;

        if (this.el.disconnectButton) {
            this.el.disconnectButton.disabled = false;
            this.el.disconnectButton.innerHTML = '<i class="fas fa-phone-slash"></i> 通話を終了';
        }

        setTimeout(() => {
            this._remoteDisconnectHandled = false;
            this._incomingCallHandled = false;
        }, 1000);

        await this.refreshOnlineList();
    }

    showUserListSection(visible) {
        const section = document.querySelector('.user-list-section') || this.el.userList?.closest('section') || this.el.userList?.parentElement;
        if (section) section.style.display = visible ? '' : 'none';
        const mainLayout = document.querySelector('.main-layout');
        if (mainLayout) mainLayout.classList.toggle('in-call', !visible);
    }

    async cleanup() {
        // 旧1対1WebRTC用のクリーンアップ。メッシュ通話には影響しないが、
        // beforeunload時に既存this.peer（通常Peer）を破棄する役割は残す
        const peer = this.peer;
        this.peer = null;
        if (peer) { try { peer.destroy(); } catch (_) { } }
    }

    handleReceivedData(data) {
        if (!data || typeof data !== 'object') return;
        if (data.type === 'MEDIA_STATE') {
            // 旧1対1WebRTC用。メッシュ通話では meshHandleData が処理する
            return;
        }
        console.log('Received:', data);
    }

    // =====================================================
    // ローカルチャットDB
    // =====================================================
    _loadLocalChatDB() {
        try {
            this.localChatDB = JSON.parse(localStorage.getItem('svc_chat_db') || '{}');
        } catch (_) { this.localChatDB = {}; }
    }
    _saveLocalChatDB() {
        const keys = Object.keys(this.localChatDB);
        // 会話数の上限を緩めに（クラウドから過去履歴を取り込むため）
        if (keys.length > 200) keys.slice(0, keys.length - 200).forEach(k => delete this.localChatDB[k]);
        Object.keys(this.localChatDB).forEach(k => {
            // 1会話あたり最大1000件まで保持（古いものから削る）
            if (this.localChatDB[k].length > 1000) this.localChatDB[k] = this.localChatDB[k].slice(-1000);
        });
        try {
            localStorage.setItem('svc_chat_db', JSON.stringify(this.localChatDB));
        } catch (e) {
            // localStorage の容量オーバー時はファイル添付メッセージのデータ部だけ落として再試行
            console.warn('[svc_chat_db] localStorage 容量オーバー。ファイル添付のdata部を破棄して再試行');
            try {
                const compact = JSON.parse(JSON.stringify(this.localChatDB));
                for (const k of Object.keys(compact)) {
                    const arr = compact[k];
                    if (!Array.isArray(arr)) continue;
                    for (const m of arr) {
                        if (m && m.file && m.file.data) {
                            // 大きい添付は localStorage では保持できないのでメタだけ残す
                            // 元データは Firebase にあるので、再アクセス時に取得可能
                            m.file = { name: m.file.name, type: m.file.type, _dropped: true };
                        }
                    }
                }
                localStorage.setItem('svc_chat_db', JSON.stringify(compact));
            } catch (e2) {
                console.error('[svc_chat_db] 保存失敗:', e2);
            }
        }
    }

    // =====================================================
    // クラウド（Firebase）からチャット履歴を同期
    // =====================================================
    // - ログイン直後にバックグラウンドで呼び出す
    // - DM: friendNames から会話キーを構築
    // - グループ: myGroups から会話キーを構築
    // - 各会話で「ローカルにある最新の ts」以降のメッセージのみ取得して localChatDB にマージ
    // - 取り込んだ後、UIが既にレンダリングされている画面があれば再描画
    async _syncChatHistoryFromCloud() {
        if (!this.myName) return;
        // 重複実行ガード（短期間に複数回呼ばれても1回だけ）
        if (this._chatSyncInProgress) return;
        this._chatSyncInProgress = true;

        try {
            // 対象の convKey 一覧を作る
            const convKeys = new Set();
            if (this.friendNames && this.friendNames.size > 0) {
                for (const name of this.friendNames) {
                    if (name && name !== this.myName) convKeys.add(this._dmKey(name));
                }
            }
            // 過去にDMしたことがある相手も含める（フレンド解除されたケース）
            for (const k of Object.keys(this.localChatDB || {})) {
                if (k.startsWith('dm:') || k.startsWith('grp:')) convKeys.add(k);
            }
            // 自分が所属するグループ
            if (Array.isArray(this.myGroups)) {
                for (const g of this.myGroups) {
                    if (g && g.id) convKeys.add(this._groupKey(g.id));
                }
            }

            if (convKeys.size === 0) return;

            // 並列に取得（最大10並列ずつ）
            const keysArr = Array.from(convKeys);
            const concurrency = 10;
            const updatedKeys = new Set();
            for (let i = 0; i < keysArr.length; i += concurrency) {
                const batch = keysArr.slice(i, i + concurrency);
                await Promise.all(batch.map(async (convKey) => {
                    // ローカルにある最新の ts を求める（差分取得）
                    const localMsgs = this.localChatDB[convKey] || [];
                    let latestTs = 0;
                    for (const m of localMsgs) {
                        if (m && typeof m.ts === 'number' && m.ts > latestTs) latestTs = m.ts;
                    }
                    const remoteMsgs = await FbAPI.fetchChatMessages(convKey, latestTs);
                    if (!remoteMsgs || remoteMsgs.length === 0) {
                        // ローカルに無いが Firebase にも無い場合でも、取り消し状態の更新が
                        // 取り込めるよう、ローカル既存メッセージとの差分マージをかける
                        // （ローカルのみで存在し、Firebase 上で recalled になっている可能性は
                        //  別途取得時に判定されるが、ここでは追加メッセージが無い場合スキップ）
                        return;
                    }
                    if (!this.localChatDB[convKey]) this.localChatDB[convKey] = [];
                    const arr = this.localChatDB[convKey];
                    // 既存メッセージを msgId でインデックス
                    const idx = new Map();
                    for (const m of arr) {
                        if (m && m.msgId) idx.set(m.msgId, m);
                    }
                    let changed = false;
                    for (const rm of remoteMsgs) {
                        if (!rm || !rm.msgId) continue;
                        const existing = idx.get(rm.msgId);
                        if (existing) {
                            // 取り消しなどの状態変化を反映
                            if (rm.recalled && !existing.recalled) {
                                existing.recalled = true;
                                existing.content = '';
                                if (existing.file) delete existing.file;
                                existing.recalledAt = rm.recalledAt || Date.now();
                                changed = true;
                            }
                        } else {
                            arr.push(rm);
                            idx.set(rm.msgId, rm);
                            changed = true;
                        }
                    }
                    if (changed) {
                        // ts 昇順に並べ替え
                        arr.sort((a, b) => (a.ts || 0) - (b.ts || 0));
                        updatedKeys.add(convKey);
                    }
                }));
            }

            if (updatedKeys.size > 0) {
                this._saveLocalChatDB();
                // 開いている画面があれば再描画
                this._refreshOpenChatViews(updatedKeys);
                // 未読バッジも再計算
                try { this._recomputeAllUnreadBadges(); } catch (_) { }
            }

            // バックグラウンドで保持期限切れのメッセージをFirebaseから削除（90日超）
            FbAPI.pruneExpiredChats(Array.from(convKeys)).catch(() => { });
        } catch (e) {
            console.warn('[_syncChatHistoryFromCloud]', e);
        } finally {
            this._chatSyncInProgress = false;
        }
    }

    // 取り込んだ会話のうち、開いている画面を再描画
    _refreshOpenChatViews(updatedKeys) {
        if (!updatedKeys || updatedKeys.size === 0) return;
        // DMモーダルが開いていて該当の相手なら再描画
        try {
            if (this.el.dmModal?.classList.contains('visible')) {
                if (this.dmPartner) {
                    const key = this._dmKey(this.dmPartner);
                    if (updatedKeys.has(key)) {
                        this._renderDmMessages(this.dmPartner);
                    }
                }
                // DM会話一覧が表示されている場合
                this._renderDmConversationList?.();
            }
            // グループモーダル
            if (this.el.groupModal?.classList.contains('visible')) {
                if (this.currentGroupId) {
                    const key = this._groupKey(this.currentGroupId);
                    if (updatedKeys.has(key)) {
                        this._renderGroupMessages?.(this.currentGroupId);
                    }
                }
            }
        } catch (e) {
            console.warn('[_refreshOpenChatViews]', e);
        }
    }
    // ---------- 未読状態の永続化 ----------
    _lastReadStorageKey() {
        // ユーザー単位で分離（同じ端末に複数アカウントが残るケース対策）
        return 'svc_last_read_' + (this.myName || '_anon');
    }
    _loadLastReadTs() {
        try {
            const key = this._lastReadStorageKey();
            this.lastReadTs = JSON.parse(localStorage.getItem(key) || '{}');
        } catch (_) { this.lastReadTs = {}; }
    }
    _saveLastReadTs() {
        try {
            const key = this._lastReadStorageKey();
            localStorage.setItem(key, JSON.stringify(this.lastReadTs));
        } catch (_) { }
    }
    _markAsRead(convKey) {
        this.lastReadTs[convKey] = Date.now();
        this._saveLastReadTs();
    }

    // =====================================================
    // 既読機能
    // =====================================================
    // 自分が「未読のうち相手から来たメッセージ」を読んだことを送信側に通知する
    // - DM: 相手1人に read_receipt を送信
    // - グループ: 自分以外のメンバー全員に read_receipt を送信
    _sendReadReceiptForConv(convKey) {
        if (!convKey) return;
        const msgs = this.localChatDB[convKey] || [];
        if (msgs.length === 0) return;
        // 「相手送信のメッセージ」のうち、まだ自分のreadByに含まれていないものを集める
        // （= 既読通知をまだ送っていないもの）
        const targetMsgIds = [];
        for (const m of msgs) {
            if (!m || !m.msgId) continue;
            if (m.type === 'system' || m.type === 'admin_broadcast') continue;
            if (m.from === this.myName) continue;
            if (!Array.isArray(m.readBy)) m.readBy = [];
            if (!m.readBy.includes(this.myName)) {
                m.readBy.push(this.myName);
                targetMsgIds.push(m.msgId);
            }
        }
        if (targetMsgIds.length === 0) return;
        this._saveLocalChatDB();

        if (convKey.startsWith('dm:')) {
            // 相手だけに送信
            const parts = convKey.slice(3).split('|');
            const partner = parts.find(p => p !== this.myName);
            if (!partner) return;
            const payload = { convType: 'dm', convKey, msgIds: targetMsgIds };
            FbAPI.sendSignal(this.token, partner, 'read_receipt', encodeURIComponent(JSON.stringify(payload))).catch(() => { });
        } else if (convKey.startsWith('grp:')) {
            const gid = convKey.slice(4);
            const group = this.myGroups.find(g => g.id === gid);
            if (!group?.members) return;
            const payload = { convType: 'group', convKey, msgIds: targetMsgIds, groupId: gid };
            for (const m of group.members) {
                if (m === this.myName) continue;
                FbAPI.sendSignal(this.token, m, 'read_receipt', encodeURIComponent(JSON.stringify(payload))).catch(() => { });
            }
        }
    }

    // 他者からの既読通知を受け取って、自分のメッセージの readBy に追加する
    _applyReadReceipt(fromName, payload) {
        if (!payload || !payload.convKey || !Array.isArray(payload.msgIds)) return;
        const convKey = payload.convKey;
        // 安全のため: DMの場合、convKeyに自分の名前が含まれるかチェック
        if (convKey.startsWith('dm:')) {
            const parts = convKey.slice(3).split('|');
            if (!parts.includes(this.myName) || !parts.includes(fromName)) return;
        } else if (convKey.startsWith('grp:')) {
            // グループの場合、自分が所属しているか
            const gid = convKey.slice(4);
            if (!this.myGroups.some(g => g.id === gid)) return;
        } else {
            return;
        }
        const msgs = this.localChatDB[convKey];
        if (!msgs) return;
        const msgIdSet = new Set(payload.msgIds);
        let changed = false;
        for (const m of msgs) {
            if (!m || !m.msgId) continue;
            if (!msgIdSet.has(m.msgId)) continue;
            if (m.from !== this.myName) continue; // 自分が送ったメッセージにだけ既読を付ける
            if (!Array.isArray(m.readBy)) m.readBy = [];
            if (!m.readBy.includes(fromName)) {
                m.readBy.push(fromName);
                changed = true;
            }
        }
        if (changed) {
            this._saveLocalChatDB();
            // 表示中のチャットなら即時再描画
            if (convKey.startsWith('dm:')) {
                const parts = convKey.slice(3).split('|');
                const partner = parts.find(p => p !== this.myName);
                if (this.el.dmModal?.classList.contains('visible') && this.dmPartner === partner) {
                    this._renderDmMessages(partner);
                }
            } else if (convKey.startsWith('grp:')) {
                const gid = convKey.slice(4);
                if (this.el.groupModal?.classList.contains('visible') && this.currentGroupId === gid) {
                    this._renderGroupMessages(gid);
                }
            }
        }
    }

    // 指定会話の未読数を localChatDB から算出（自分以外＆システムメッセージ以外＆最終既読より新しい）
    _countUnread(convKey) {
        const msgs = this.localChatDB[convKey] || [];
        const last = this.lastReadTs[convKey] || 0;
        let n = 0;
        for (const m of msgs) {
            if (!m || m.type === 'system') continue;
            if (m.from === this.myName) continue;
            if ((m.ts || 0) > last) n++;
        }
        return n;
    }
    // すべてのDM・グループの未読数を再計算してバッジを更新
    _recomputeAllUnreadBadges() {
        // DM: 自分を含む dm: キーのみ対象
        this.dmUnreadCounts = {};
        Object.keys(this.localChatDB).forEach(k => {
            if (!k.startsWith('dm:')) return;
            // dm:A|B → 自分が会話の当事者でなければスキップ
            const parts = k.slice(3).split('|');
            if (parts.length !== 2) return;
            if (!parts.includes(this.myName)) return;
            const partner = parts.find(p => p !== this.myName);
            if (!partner) return;
            const n = this._countUnread(k);
            if (n > 0) this.dmUnreadCounts[partner] = n;
        });
        this._updateDmBadge();
        // グループ: 現在所属しているグループのみ対象（退出済みの古いキーは無視）
        this.groupUnreadCounts = {};
        const activeGroupIds = new Set((this.myGroups || []).map(g => g.id));
        Object.keys(this.localChatDB).forEach(k => {
            if (!k.startsWith('grp:')) return;
            const gid = k.slice(4);
            if (!activeGroupIds.has(gid)) return;
            const n = this._countUnread(k);
            if (n > 0) this.groupUnreadCounts[gid] = n;
        });
        this._updateGroupBadge();
    }
    _dmKey(partnerName) { return `dm:${[this.myName, partnerName].sort().join('|')}`; }
    _groupKey(groupId) { return `grp:${groupId}`; }
    _genMsgId() {
        return `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    }
    _addMessage(key, msg) {
        if (!this.localChatDB[key]) this.localChatDB[key] = [];
        // msgIdが無い古いメッセージのために、ts+from+contentでフォールバック比較もする
        if (msg.msgId) {
            if (this.localChatDB[key].some(m => m.msgId === msg.msgId)) return false;
        } else {
            // 同じts/from/contentが既にあれば重複とみなす
            if (this.localChatDB[key].some(m => !m.msgId && m.ts === msg.ts && m.from === msg.from && m.content === msg.content && m.type === msg.type)) return false;
        }
        this.localChatDB[key].push(msg);
        this._saveLocalChatDB();
        // クラウド（Firebase）にも保存。
        // - 送信者が自分のメッセージのみアップロード（重複防止）
        // - system メッセージはローカル表示用なので保存しない
        // - msgId が無いメッセージはキー化できないので保存しない
        if (msg && msg.msgId && msg.from === this.myName && msg.type !== 'system') {
            FbAPI.saveChatMessage(key, msg).catch(() => { });
        }
        return true;
    }

    // =====================================================
    // メッセージ取り消し機能
    // =====================================================
    // ローカルDB上のメッセージを「取り消し済み」にする
    _markMessageRecalled(convKey, msgId) {
        const msgs = this.localChatDB[convKey];
        if (!msgs) return null;
        const m = msgs.find(x => x.msgId === msgId);
        if (!m) return null;
        m.recalled = true;
        m.content = '';
        if (m.file) delete m.file;
        m.recalledAt = Date.now();
        this._saveLocalChatDB();
        // クラウドにも反映（送信者本人なら）
        // 取り消し送信元（自分）と相手（受信側）の両方でこの関数が呼ばれるが、
        // Firebase に保存されているメッセージの所有は送信者なので、
        // 送信者のローカルだけで更新を出せば十分。
        if (m.from === this.myName) {
            FbAPI.updateChatMessage(convKey, msgId, {
                recalled: true,
                content: '',
                file: null,
                recalledAt: m.recalledAt
            }).catch(() => { });
        }
        return m;
    }

    // 取り消し操作の起点: バブルがクリックされたら確認モーダルを出す
    _openRecallConfirm(convType, convKey, msgId) {
        this._pendingRecall = { convType, convKey, msgId };
        if (this.el.recallConfirmModal) this.el.recallConfirmModal.classList.add('visible');
    }

    _closeRecallConfirm() {
        this._pendingRecall = null;
        if (this.el.recallConfirmModal) this.el.recallConfirmModal.classList.remove('visible');
    }

    async _confirmRecall() {
        const pending = this._pendingRecall;
        this._closeRecallConfirm();
        if (!pending) return;
        const { convType, convKey, msgId } = pending;

        // ローカル更新
        const updated = this._markMessageRecalled(convKey, msgId);
        if (!updated) {
            this.showNotification('エラー', 'メッセージが見つかりませんでした', 'error');
            return;
        }

        // 描画更新
        if (convType === 'dm') {
            if (this.dmPartner) this._renderDmMessages(this.dmPartner);
        } else if (convType === 'group') {
            if (this.currentGroupId) this._renderGroupMessages(this.currentGroupId);
        }

        // 相手に通知（msg_recall シグナル）
        try {
            if (convType === 'dm') {
                // convKey は dm:A|B 形式。partner を取り出す
                const parts = convKey.startsWith('dm:') ? convKey.slice(3).split('|') : [];
                const partner = parts.find(p => p !== this.myName);
                if (partner) {
                    const payload = { convType: 'dm', msgId };
                    await FbAPI.sendSignal(this.token, partner, 'msg_recall', encodeURIComponent(JSON.stringify(payload)));
                }
            } else if (convType === 'group') {
                // convKey は grp:GROUPID
                const gid = convKey.startsWith('grp:') ? convKey.slice(4) : null;
                const group = gid ? this.myGroups.find(g => g.id === gid) : null;
                if (group?.members) {
                    const payload = { convType: 'group', convKey, groupId: gid, msgId };
                    const data = encodeURIComponent(JSON.stringify(payload));
                    for (const member of group.members) {
                        if (member === this.myName) continue;
                        FbAPI.sendSignal(this.token, member, 'msg_recall', data).catch(() => { });
                    }
                }
            }
        } catch (e) {
            console.warn('取り消し通知の送信失敗:', e);
        }
    }

    // 相手から msg_recall シグナルを受信したとき
    _applyRemoteRecall(fromName, payload) {
        if (!payload || !payload.msgId) return;
        let convKey = null;
        let convType = null;
        if (payload.convType === 'dm') {
            convKey = this._dmKey(fromName);
            convType = 'dm';
        } else if (payload.convType === 'group') {
            // payload.convKey or payload.groupId から決める
            if (payload.convKey && payload.convKey.startsWith('grp:')) {
                convKey = payload.convKey;
            } else if (payload.groupId) {
                convKey = this._groupKey(payload.groupId);
            }
            convType = 'group';
            // 自分が所属しているグループか確認
            if (convKey) {
                const gid = convKey.slice(4);
                if (!this.myGroups.some(g => g.id === gid)) return;
            }
        }
        if (!convKey) return;

        // 取り消す対象は「fromName が送ったメッセージ」のみ（なりすまし防止）
        const msgs = this.localChatDB[convKey];
        if (!msgs) return;
        const target = msgs.find(m => m.msgId === payload.msgId);
        if (!target) return;
        if (target.from !== fromName) return;

        this._markMessageRecalled(convKey, payload.msgId);

        // 表示中なら再描画
        if (convType === 'dm') {
            if (this.el.dmModal?.classList.contains('visible') && this.dmPartner === fromName) {
                this._renderDmMessages(fromName);
            }
        } else if (convType === 'group') {
            const gid = convKey.slice(4);
            if (this.el.groupModal?.classList.contains('visible') && this.currentGroupId === gid) {
                this._renderGroupMessages(gid);
            }
        }
    }

    // 取り消し用コンテキストメニュー（右クリック / 長押し）の設定
    _setupRecallMenu() {
        if (this._recallMenuSetup) return;
        this._recallMenuSetup = true;

        // 自分のメッセージバブルに対するコンテキストメニュー
        const onContextMenu = (e) => {
            const bubble = e.target.closest('.chat-msg.mine .chat-msg-bubble');
            if (!bubble) return;
            if (bubble.classList.contains('recalled')) return;
            const msgEl = bubble.closest('.chat-msg');
            const msgId = msgEl?.dataset?.msgid;
            const ctxType = msgEl?.dataset?.ctxtype;
            const ctxKey = msgEl?.dataset?.ctxkey;
            if (!msgId || !ctxType || !ctxKey) return;
            e.preventDefault();
            this._showMsgActionMenu(e.clientX, e.clientY, ctxType, ctxKey, msgId);
        };

        // 長押し（モバイル）
        let longPressTimer = null;
        let longPressTarget = null;
        const onTouchStart = (e) => {
            const bubble = e.target.closest('.chat-msg.mine .chat-msg-bubble');
            if (!bubble) return;
            if (bubble.classList.contains('recalled')) return;
            longPressTarget = bubble;
            longPressTimer = setTimeout(() => {
                const msgEl = bubble.closest('.chat-msg');
                const msgId = msgEl?.dataset?.msgid;
                const ctxType = msgEl?.dataset?.ctxtype;
                const ctxKey = msgEl?.dataset?.ctxkey;
                if (!msgId || !ctxType || !ctxKey) return;
                const rect = bubble.getBoundingClientRect();
                this._showMsgActionMenu(rect.left, rect.bottom, ctxType, ctxKey, msgId);
            }, 550);
        };
        const cancelLongPress = () => {
            if (longPressTimer) { clearTimeout(longPressTimer); longPressTimer = null; }
            longPressTarget = null;
        };

        // DM・グループ両方に設定
        [this.el.dmMessages, this.el.groupMessages].forEach(container => {
            if (!container) return;
            container.addEventListener('contextmenu', onContextMenu);
            container.addEventListener('touchstart', onTouchStart, { passive: true });
            container.addEventListener('touchend', cancelLongPress);
            container.addEventListener('touchmove', cancelLongPress);
            container.addEventListener('touchcancel', cancelLongPress);
        });

        // メニュー外クリックで閉じる
        document.addEventListener('click', (e) => {
            if (!this.el.msgActionMenu) return;
            if (this.el.msgActionMenu.style.display === 'none') return;
            if (e.target.closest('#msgActionMenu')) return;
            this._hideMsgActionMenu();
        });

        // メニューの「取り消す」ボタン
        if (this.el.msgRecallBtn) {
            this.el.msgRecallBtn.addEventListener('click', () => {
                const target = this._currentMsgMenuTarget;
                this._hideMsgActionMenu();
                if (target) this._openRecallConfirm(target.convType, target.convKey, target.msgId);
            });
        }

        // 確認モーダルのボタン
        if (this.el.recallConfirmBtn) {
            this.el.recallConfirmBtn.addEventListener('click', () => this._confirmRecall());
        }
        if (this.el.recallCancelBtn) {
            this.el.recallCancelBtn.addEventListener('click', () => this._closeRecallConfirm());
        }
    }

    _showMsgActionMenu(x, y, ctxType, ctxKey, msgId) {
        if (!this.el.msgActionMenu) return;
        // ctxType ('dm'/'group') と ctxKey を convKey に正規化
        let convKey;
        if (ctxType === 'dm') {
            convKey = this._dmKey(ctxKey);
        } else if (ctxType === 'group') {
            convKey = this._groupKey(ctxKey);
        } else {
            return;
        }
        this._currentMsgMenuTarget = { convType: ctxType, convKey, msgId };

        const menu = this.el.msgActionMenu;
        menu.style.display = '';
        // 一旦表示してサイズ取得 → 画面端調整
        const menuRect = menu.getBoundingClientRect();
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        let left = x;
        let top = y;
        if (left + menuRect.width + 8 > vw) left = vw - menuRect.width - 8;
        if (top + menuRect.height + 8 > vh) top = vh - menuRect.height - 8;
        if (left < 8) left = 8;
        if (top < 8) top = 8;
        menu.style.left = left + 'px';
        menu.style.top = top + 'px';
    }

    _hideMsgActionMenu() {
        if (this.el.msgActionMenu) this.el.msgActionMenu.style.display = 'none';
        this._currentMsgMenuTarget = null;
    }

    // =====================================================
    // DM機能
    // =====================================================
    openDmModal() {
        this.el.dmModal.classList.add('visible');
        this._showDmConversationList();
    }
    _showDmConversationList() {
        this.dmPartner = null;
        this.el.dmChatArea.style.display = 'none';
        this.el.dmConversationList.style.display = '';
        this.el.dmCallBtn.style.display = 'none';
        this.el.dmModalTitle.textContent = 'ダイレクトメッセージ';
        // 新規DM FABを表示
        if (this.el.newDmFab) this.el.newDmFab.style.display = '';
        this._renderDmConversationList();
    }
    async _startNewDm() {
        const name = this.el.newDmTargetName?.value.trim();
        if (this.el.newDmError) this.el.newDmError.textContent = '';
        if (!name) { if (this.el.newDmError) this.el.newDmError.textContent = '名前を入力してください'; return; }
        if (name === this.myName) { if (this.el.newDmError) this.el.newDmError.textContent = '自分とはDMできません'; return; }
        if (this.blockedUsers.has(name)) { if (this.el.newDmError) this.el.newDmError.textContent = 'ブロック中のユーザーです'; return; }

        // ユーザーが実在するか確認
        const confirmBtn = this.el.newDmConfirmBtn;
        const originalHTML = confirmBtn?.innerHTML;
        if (confirmBtn) {
            confirmBtn.disabled = true;
            confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 確認中...';
        }
        try {
            const exists = await FbAPI._accountExists(name);
            if (!exists) {
                if (this.el.newDmError) this.el.newDmError.textContent = 'そのユーザーは存在しません';
                return;
            }
        } catch (e) {
            if (this.el.newDmError) this.el.newDmError.textContent = '確認に失敗しました。通信状態を確認してください';
            return;
        } finally {
            if (confirmBtn) {
                confirmBtn.disabled = false;
                if (originalHTML) confirmBtn.innerHTML = originalHTML;
            }
        }

        this.el.newDmModal.classList.remove('visible');
        // 既存の会話がなくても会話を開始（メッセージ送信時に自動的にDBに記録される）
        this._openDmChat(name);
    }
    _renderDmConversationList() {
        const convKeys = Object.keys(this.localChatDB).filter(k => k.startsWith('dm:') && k.includes(this.myName));
        const allNames = new Set([...this.friendNames]);
        convKeys.forEach(k => {
            const parts = k.replace('dm:', '').split('|');
            parts.forEach(p => { if (p !== this.myName) allNames.add(p); });
        });

        if (allNames.size === 0) {
            this.el.dmConversationList.innerHTML = '<div class="friend-empty"><i class="fas fa-comment-slash"></i><p>会話がありません</p><p style="font-size:0.85rem;opacity:0.7;margin-top:0.5rem">右下の＋ボタンから新規DMを開始できます</p></div>';
            return;
        }

        // 各DMの最終メッセージ時刻を計算して、新しい順にソート
        // メッセージが0件の相手（フレンドだけど未会話）は最後
        const namesArr = [...allNames];
        const lastTsByName = {};
        namesArr.forEach(name => {
            const msgs = this.localChatDB[this._dmKey(name)] || [];
            const last = msgs[msgs.length - 1];
            lastTsByName[name] = last?.ts || 0;
        });
        namesArr.sort((a, b) => {
            const ta = lastTsByName[a];
            const tb = lastTsByName[b];
            if (ta === tb) return a.localeCompare(b, 'ja');
            return tb - ta; // 新しいものが上
        });

        let html = '';
        namesArr.forEach(name => {
            const key = this._dmKey(name);
            const msgs = this.localChatDB[key] || [];
            const last = msgs[msgs.length - 1];
            const unread = this.dmUnreadCounts[name] || 0;
            const preview = last ? this.escapeHtml(last.content?.slice(0, 40) || (last.file ? '📎 ファイル' : '')) : 'メッセージはありません';
            const isAdminContact = (name === '管理者');
            const adminBadge = isAdminContact ? '<span style="display:inline-flex;align-items:center;gap:0.2rem;font-size:0.65rem;font-weight:700;color:#fff;background:linear-gradient(135deg,#dc2626,#f97316);padding:0.1rem 0.4rem;border-radius:4px;margin-left:0.4rem;vertical-align:middle"><i class="fas fa-shield-halved" style="font-size:0.6rem"></i>公式</span>' : '';
            const avUrl = !isAdminContact ? this.avatarCache[name] : null;
            let avatarHtml;
            if (isAdminContact) {
                avatarHtml = `<div class="friend-item-avatar" style="background:linear-gradient(135deg,#dc2626,#f97316);color:#fff" data-uname="${this.escapeHtml(name)}"><i class="fas fa-shield-halved"></i></div>`;
            } else if (avUrl) {
                avatarHtml = `<div class="friend-item-avatar has-image" data-uname="${this.escapeHtml(name)}" style="background-image:url('${avUrl}')"></div>`;
            } else {
                avatarHtml = `<div class="friend-item-avatar" data-uname="${this.escapeHtml(name)}">${this.escapeHtml(name.charAt(0).toUpperCase())}</div>`;
            }
            html += `<div class="dm-conv-item" data-name="${this.escapeHtml(name)}">
                ${avatarHtml}
                <div class="dm-conv-info">
                    <span class="dm-conv-name">${this.escapeHtml(name)}${adminBadge}</span>
                    <span class="dm-conv-preview">${preview}</span>
                </div>
                ${unread > 0 ? `<span class="dm-unread-badge">${unread}</span>` : ''}
            </div>`;
        });
        this.el.dmConversationList.innerHTML = html;
        this.el.dmConversationList.querySelectorAll('.dm-conv-item').forEach(el => {
            el.addEventListener('click', () => this._openDmChat(el.dataset.name));
        });

        // 未取得のアバターをバックグラウンドで取得
        const targets = namesArr.filter(n => n !== '管理者');
        this._fetchAvatarsFor(targets).then(() => this._refreshAvatarsInDom());
    }
    _openDmChat(name) {
        this.dmPartner = name;
        const key = this._dmKey(name);
        this._markAsRead(key);
        // 既読通知を送信（まだ送っていない受信メッセージに対して）
        this._sendReadReceiptForConv(key);
        this._recomputeAllUnreadBadges();
        this.el.dmConversationList.style.display = 'none';
        this.el.dmChatArea.style.display = '';
        this.el.dmModalTitle.textContent = `💬 ${name}`;
        this.el.dmCallBtn.style.display = '';
        // 新規DM FABはチャット画面では非表示
        if (this.el.newDmFab) this.el.newDmFab.style.display = 'none';
        this._renderDmMessages(name);
        if (this.el.dmInput) this.el.dmInput.focus();
    }
    _renderDmMessages(name) {
        const key = this._dmKey(name);
        const msgs = this.localChatDB[key] || [];
        // メッセージから他者のFrom名を集めて先にアバター取得
        const otherNames = [...new Set(msgs.filter(m => m.from && m.from !== this.myName && m.type !== 'system').map(m => m.from))];
        const ctx = { type: 'dm', partner: name };
        this.el.dmMessages.innerHTML = msgs.map(m => this._renderMessageBubble(m, ctx)).join('');
        this.el.dmMessages.scrollTop = this.el.dmMessages.scrollHeight;
        // 取得して反映
        if (otherNames.length > 0) {
            this._fetchAvatarsFor(otherNames).then(() => this._refreshAvatarsInDom());
        }
    }
    async _sendDmMessage() {
        const text = this.el.dmInput?.value.trim();
        if (!text || !this.dmPartner) return;
        this.el.dmInput.value = '';
        const msg = { msgId: this._genMsgId(), from: this.myName, content: text, ts: Date.now(), type: 'text' };
        const key = this._dmKey(this.dmPartner);
        this._addMessage(key, msg);
        this._renderDmMessages(this.dmPartner);
        try {
            await FbAPI.sendSignal(this.token, this.dmPartner, 'dm', encodeURIComponent(JSON.stringify(msg)));
        } catch (_) { }
    }
    async _sendDmFile(file) {
        if (!file || !this.dmPartner) return;
        if (file.size > 5 * 1024 * 1024) { this.showNotification('エラー', 'ファイルは5MB以下にしてください', 'error'); return; }
        const reader = new FileReader();
        reader.onload = async e => {
            const msg = { msgId: this._genMsgId(), from: this.myName, content: '', ts: Date.now(), type: 'file', file: { name: file.name, type: file.type, data: e.target.result } };
            const key = this._dmKey(this.dmPartner);
            this._addMessage(key, msg);
            this._renderDmMessages(this.dmPartner);
            try {
                await FbAPI.sendSignal(this.token, this.dmPartner, 'dm', encodeURIComponent(JSON.stringify(msg)));
            } catch (_) { }
        };
        reader.readAsDataURL(file);
        if (this.el.dmFileInput) this.el.dmFileInput.value = '';
    }
    _receiveDmMessage(fromName, msg) {
        const key = this._dmKey(fromName);
        const added = this._addMessage(key, msg);
        if (!added) return; // 重複なら何もしない
        // 管理者からのお知らせは目立つ通知も出す
        if (msg.type === 'admin_broadcast') {
            const preview = (msg.content || '').slice(0, 60);
            this.showNotification('📢 管理者からのお知らせ', preview + ((msg.content || '').length > 60 ? '…' : ''), 'info');
        }
        if (this.el.dmModal.classList.contains('visible') && this.dmPartner === fromName) {
            // この会話を開いている → 既読扱い
            this._markAsRead(key);
            // 既読通知を相手に送信
            this._sendReadReceiptForConv(key);
            this._renderDmMessages(fromName);
            this._recomputeAllUnreadBadges();
        } else {
            // 開いていない → 未読として再計算してバッジ更新
            this._recomputeAllUnreadBadges();
            // 会話一覧が表示中なら一覧の未読バッジも更新
            if (this.el.dmModal.classList.contains('visible') && !this.dmPartner) {
                this._renderDmConversationList();
            }
        }
    }
    _updateDmBadge() {
        const total = Object.values(this.dmUnreadCounts).reduce((a, b) => a + b, 0);
        if (this.el.dmBadge) {
            if (total > 0) {
                this.el.dmBadge.style.display = 'flex';
                this.el.dmBadge.textContent = total > 99 ? '99+' : total;
            } else {
                this.el.dmBadge.style.display = 'none';
                this.el.dmBadge.textContent = '';
            }
        }
    }

    // フレンドが名前を変えた時のローカルDM履歴マージ処理。
    // 旧キー (dm:[me,oldName].sort()) の履歴を新キー (dm:[me,newName].sort()) へ統合し、
    // 重複（msgId 一致、または ts/from/content/type 一致）を排除する。
    // メッセージ内の from === oldName も newName に書き換えて表示の一貫性を保つ。
    _handlePartnerNameChanged(oldName, newName) {
        if (!oldName || !newName || oldName === newName) return;
        if (!this.myName || oldName === this.myName) return;

        const oldKey = `dm:${[this.myName, oldName].sort().join('|')}`;
        const newKey = `dm:${[this.myName, newName].sort().join('|')}`;

        // 履歴のマージ
        const oldMsgs = this.localChatDB[oldKey];
        if (Array.isArray(oldMsgs) && oldMsgs.length > 0) {
            const remapped = oldMsgs.map(m => {
                if (m && m.from === oldName) return { ...m, from: newName };
                return m;
            });
            if (oldKey === newKey) {
                // 念のためのno-op（自分の名前変更ケース等を想定）
                this.localChatDB[oldKey] = remapped;
            } else {
                if (!Array.isArray(this.localChatDB[newKey])) this.localChatDB[newKey] = [];
                const existing = this.localChatDB[newKey];
                const seenIds = new Set(existing.filter(m => m && m.msgId).map(m => m.msgId));
                const seenFallback = new Set(
                    existing.filter(m => m && !m.msgId)
                        .map(m => `${m.ts}|${m.from}|${m.type}|${m.content}`)
                );
                for (const m of remapped) {
                    if (!m) continue;
                    if (m.msgId) {
                        if (seenIds.has(m.msgId)) continue;
                        seenIds.add(m.msgId);
                    } else {
                        const k = `${m.ts}|${m.from}|${m.type}|${m.content}`;
                        if (seenFallback.has(k)) continue;
                        seenFallback.add(k);
                    }
                    existing.push(m);
                }
                // タイムスタンプ順にソート
                existing.sort((a, b) => (a.ts || 0) - (b.ts || 0));
                delete this.localChatDB[oldKey];
            }
            this._saveLocalChatDB();
        } else if (this.localChatDB[oldKey]) {
            // 空配列だけ残っているケースを掃除
            delete this.localChatDB[oldKey];
            this._saveLocalChatDB();
        }

        // 既読タイムスタンプ
        if (oldKey !== newKey && Object.prototype.hasOwnProperty.call(this.lastReadTs, oldKey)) {
            const oldTs = this.lastReadTs[oldKey] || 0;
            const curTs = this.lastReadTs[newKey] || 0;
            this.lastReadTs[newKey] = Math.max(oldTs, curTs);
            delete this.lastReadTs[oldKey];
            this._saveLastReadTs?.();
        }

        // 未読カウントの引き継ぎ
        if (this.dmUnreadCounts[oldName] != null) {
            const sum = (this.dmUnreadCounts[newName] || 0) + this.dmUnreadCounts[oldName];
            if (sum > 0) this.dmUnreadCounts[newName] = sum;
            delete this.dmUnreadCounts[oldName];
        }

        // 現在開いている DM 相手が旧名なら新名に切り替えて再描画
        if (this.dmPartner === oldName) {
            this.dmPartner = newName;
            if (this.el.dmModalTitle) this.el.dmModalTitle.textContent = newName;
            this._renderDmMessages?.(newName);
        }

        // バッジ・一覧の再計算と再描画
        this._recomputeAllUnreadBadges();
        if (this.el.dmModal?.classList.contains('visible') && !this.dmPartner) {
            this._renderDmConversationList();
        }
    }

    // =====================================================
    // グループチャット
    // =====================================================
    async openGroupModal() {
        // モーダルを表示する前にリスト状態へリセットしておく
        // （前回開いた時のグループチャット画面が一瞬見えるのを防ぐ）
        this._showGroupList();
        this.el.groupModal.classList.add('visible');
        await this._loadGroups();
        // ロード完了後にもう一度リストを表示（_loadGroupsで状態が変わっている可能性に備える）
        this._showGroupList();
    }
    async _loadGroups() {
        try {
            const res = await FbAPI.getGroups(this.token);
            if (res?.ok) {
                this.myGroups = res.groups || [];
                // グループアバターをキャッシュに反映
                for (const g of this.myGroups) {
                    if (g.avatar) this.groupAvatarCache[g.id] = g.avatar;
                }
                // 進行中の通話情報を activeGroupCalls に同期
                this._syncActiveGroupCallsFromGroups();
                // 各グループの activeCall をリアルタイム購読（後から開始される通話にも反応）
                this._subscribeAllGroupActiveCalls();
            }
        } catch (_) { }
    }

    // myGroups の activeCall を activeGroupCalls Map に反映
    _syncActiveGroupCallsFromGroups() {
        if (!this.activeGroupCalls) this.activeGroupCalls = new Map();
        const validGroupIds = new Set();
        for (const g of this.myGroups) {
            validGroupIds.add(g.id);
            if (g.activeCall && g.activeCall.hostName) {
                this.activeGroupCalls.set(g.id, {
                    hostName: g.activeCall.hostName,
                    hostPeerId: g.activeCall.hostPeerId || null,
                    groupName: g.name,
                    startedAt: g.activeCall.startedAt || Date.now()
                });
            } else {
                this.activeGroupCalls.delete(g.id);
            }
        }
        // 自分がもう所属していないグループの entry を消す
        for (const gid of Array.from(this.activeGroupCalls.keys())) {
            if (!validGroupIds.has(gid)) this.activeGroupCalls.delete(gid);
        }
        // UIに反映
        this._updateGroupBadge();
        // 一覧表示中ならインジケータも更新
        if (this.el.groupModal?.classList.contains('visible') &&
            this.el.groupListArea?.style.display !== 'none') {
            this._refreshGroupListCallIndicator();
        }
        // チャット開いていればバナーも更新
        if (this.currentGroupId &&
            this.el.groupModal?.classList.contains('visible') &&
            this.el.groupChatArea?.style.display !== 'none') {
            this._updateGroupCallBanner(this.currentGroupId);
        }
    }

    // 全グループの activeCall をリアルタイム購読
    _subscribeAllGroupActiveCalls() {
        if (!this.myName) return;
        const ids = this.myGroups.map(g => g.id).sort();
        // 既に同じグループIDセットで購読中なら何もしない（毎回購読し直すと、その瞬間の変更を見逃す可能性がある）
        const newKey = ids.join('|');
        if (this._activeCallsSubKey === newKey) return;
        this._activeCallsSubKey = newKey;

        FbAPI.subscribeGroupActiveCalls(this.myName, ids, (groupId, activeCall) => {
            const group = this.myGroups.find(g => g.id === groupId);
            if (!group) return;

            const oldEntry = this.activeGroupCalls.get(groupId);
            if (activeCall && activeCall.hostName) {
                this.activeGroupCalls.set(groupId, {
                    hostName: activeCall.hostName,
                    hostPeerId: activeCall.hostPeerId || null,
                    groupName: group.name,
                    startedAt: activeCall.startedAt || Date.now()
                });
                group.activeCall = activeCall;

                // 自分が現在この通話に参加中で、かつホストが変わった場合は新ホストに接続を試みる
                if (this._meshIsInCall() && this.meshGroupId === groupId && !this.meshIsHost) {
                    const newHostPeerId = activeCall.hostPeerId;
                    const oldHostPeerId = oldEntry?.hostPeerId;
                    if (newHostPeerId && newHostPeerId !== oldHostPeerId &&
                        newHostPeerId !== this.meshMyId) {
                        // ホストが変わった！新ホストに接続を試みる
                        this._meshLog('host changed, connecting to new host:', newHostPeerId);
                        this.meshHostName = activeCall.hostName;
                        if (!this.meshPeers.has(newHostPeerId)) {
                            this._meshConnectToPeer(newHostPeerId);
                        }
                    }
                }
            } else {
                // 通話終了
                this.activeGroupCalls.delete(groupId);
                group.activeCall = null;

                // 自分がこの通話に参加中だった場合、退出処理
                if (this._meshIsInCall() && this.meshGroupId === groupId && !this.meshIsHost) {
                    this._meshLog('active call ended on Firebase, leaving');
                    this._leaveMeshCall(true).catch(() => { });
                }
            }
            // UI反映
            this._updateGroupBadge();
            if (this.el.groupModal?.classList.contains('visible') &&
                this.el.groupListArea?.style.display !== 'none') {
                this._refreshGroupListCallIndicator();
            }
            if (this.currentGroupId === groupId &&
                this.el.groupModal?.classList.contains('visible') &&
                this.el.groupChatArea?.style.display !== 'none') {
                this._updateGroupCallBanner(groupId);
            }
        });
    }
    _showGroupList() {
        this.currentGroupId = null;
        this.el.groupChatArea.style.display = 'none';
        this.el.groupListArea.style.display = '';
        this.el.groupModalTitle.textContent = 'グループチャット';
        this._renderGroupList();
    }
    _renderGroupList() {
        if (this.myGroups.length === 0) {
            this.el.groupListArea.innerHTML = '<div class="friend-empty"><i class="fas fa-door-open"></i><p>参加中のグループはありません</p></div>';
            return;
        }

        // 各グループの最終メッセージ時刻でソート（新しい順）
        const sortedGroups = [...this.myGroups].sort((a, b) => {
            const msgsA = this.localChatDB[this._groupKey(a.id)] || [];
            const msgsB = this.localChatDB[this._groupKey(b.id)] || [];
            // システムメッセージも順序判定に使う（参加直後のフィードバックが上に来るように）
            const ta = msgsA.length ? (msgsA[msgsA.length - 1].ts || 0) : 0;
            const tb = msgsB.length ? (msgsB[msgsB.length - 1].ts || 0) : 0;
            if (ta === tb) return (a.name || '').localeCompare(b.name || '', 'ja');
            return tb - ta;
        });

        this.el.groupListArea.innerHTML = sortedGroups.map(g => {
            const unread = this.groupUnreadCounts[g.id] || 0;
            // グループアバター: キャッシュ or g.avatar
            const url = this.groupAvatarCache[g.id] || g.avatar;
            // 取得済みでなければキャッシュに記録
            if (g.avatar && !(g.id in this.groupAvatarCache)) {
                this.groupAvatarCache[g.id] = g.avatar;
            }
            let avatarHtml;
            if (url) {
                avatarHtml = `<div class="friend-item-avatar group-square-avatar has-image" data-gid="${this.escapeHtml(g.id)}" style="background-image:url('${url}')"></div>`;
            } else {
                avatarHtml = `<div class="friend-item-avatar group-square-avatar" data-gid="${this.escapeHtml(g.id)}" style="background:linear-gradient(135deg,#7c3aed,#a78bfa)">${this.escapeHtml(g.name.charAt(0).toUpperCase())}</div>`;
            }
            return `<div class="dm-conv-item" data-gid="${this.escapeHtml(g.id)}" data-gname="${this.escapeHtml(g.name)}">
                ${avatarHtml}
                <div class="dm-conv-info">
                    <span class="dm-conv-name">${this.escapeHtml(g.name)}</span>
                    <span class="dm-conv-preview">${g.members ? this.escapeHtml(g.members.join(', ')) : ''}</span>
                </div>
                ${unread > 0 ? `<span class="dm-unread-badge">${unread}</span>` : ''}
            </div>`;
        }).join('');
        this.el.groupListArea.querySelectorAll('.dm-conv-item').forEach(el => {
            el.addEventListener('click', () => this._openGroupChat(el.dataset.gid, el.dataset.gname));
        });
        // 進行中通話のインジケータを反映
        this._refreshGroupListCallIndicator();
    }
    _openGroupChat(groupId, groupName) {
        this.currentGroupId = groupId;
        this.currentGroupName = groupName;
        const key = this._groupKey(groupId);
        this._markAsRead(key);
        this._sendReadReceiptForConv(key);
        this._recomputeAllUnreadBadges();
        this.el.groupListArea.style.display = 'none';
        this.el.groupChatArea.style.display = '';
        this.el.groupChatName.textContent = groupName;
        this._renderGroupMessages(groupId);
        if (this.el.groupInput) this.el.groupInput.focus();
        // 進行中グループ通話バナーを更新
        this._updateGroupCallBanner(groupId);
    }
    _renderGroupMessages(groupId) {
        const key = this._groupKey(groupId);
        const msgs = this.localChatDB[key] || [];
        const otherNames = [...new Set(msgs.filter(m => m.from && m.from !== this.myName && m.type !== 'system').map(m => m.from))];
        const group = this.myGroups.find(g => g.id === groupId);
        const memberCount = group?.members ? group.members.length : 1;
        const ctx = { type: 'group', groupId, memberCount };
        this.el.groupMessages.innerHTML = msgs.map(m => this._renderMessageBubble(m, ctx)).join('');
        this.el.groupMessages.scrollTop = this.el.groupMessages.scrollHeight;
        if (otherNames.length > 0) {
            this._fetchAvatarsFor(otherNames).then(() => this._refreshAvatarsInDom());
        }
    }
    async _createGroup() {
        const name = this.el.newGroupName?.value.trim();
        if (!name) { this.el.createGroupError.textContent = 'グループ名を入力してください'; return; }
        this.el.createGroupConfirmBtn.disabled = true;
        try {
            const avatar = this._pendingNewGroupAvatar || null;
            const res = await FbAPI.createGroup(this.token, name, avatar);
            if (res?.ok) {
                if (avatar && res.group_id) {
                    this.groupAvatarCache[res.group_id] = avatar;
                }
                this._clearNewGroupAvatar();
                this.el.createGroupModal.classList.remove('visible');
                await this._loadGroups();
                this._showGroupList();
            } else {
                this.el.createGroupError.textContent = res?.error || '作成に失敗しました';
            }
        } catch (_) { this.el.createGroupError.textContent = 'サーバーエラー'; }
        this.el.createGroupConfirmBtn.disabled = false;
    }
    async _inviteGroup() {
        const target = this.el.inviteTargetName?.value.trim();
        if (!target) { this.el.inviteGroupError.textContent = '名前を入力してください'; return; }
        this.el.inviteGroupConfirmBtn.disabled = true;
        try {
            const res = await FbAPI.inviteGroup(this.token, this.currentGroupId, target);
            if (res?.ok) {
                // 自分のmyGroupsの members も最新化（招待後の members に対象者が追加されているため）
                try { await this._loadGroups(); } catch (_) { }
                const group = this.myGroups.find(g => g.id === this.currentGroupId);
                await FbAPI.sendSignal(this.token, target, 'group_invite', encodeURIComponent(JSON.stringify({ groupId: this.currentGroupId, groupName: this.currentGroupName || group?.name })));
                this.el.inviteGroupModal.classList.remove('visible');
                this.showNotification('招待', `${target} を招待しました`, 'success');
            } else {
                this.el.inviteGroupError.textContent = res?.error || '招待に失敗しました';
            }
        } catch (_) { this.el.inviteGroupError.textContent = 'サーバーエラー'; }
        this.el.inviteGroupConfirmBtn.disabled = false;
    }
    async _leaveGroup() {
        if (!this.currentGroupId) return;
        if (!confirm(`「${this.currentGroupName}」から退出しますか？`)) return;
        try {
            const res = await FbAPI.leaveGroup(this.token, this.currentGroupId);
            if (res?.ok) {
                const group = this.myGroups.find(g => g.id === this.currentGroupId);
                if (group?.members) {
                    for (const m of group.members) {
                        if (m !== this.myName) {
                            FbAPI.sendSignal(this.token, m, 'group_member_left', encodeURIComponent(JSON.stringify({ groupId: this.currentGroupId }))).catch(() => { });
                        }
                    }
                }
                this.myGroups = this.myGroups.filter(g => g.id !== this.currentGroupId);
                this.el.groupChatArea.style.display = 'none';
                this.el.groupListArea.style.display = '';
                this._showGroupList();
            }
        } catch (_) { }
    }
    async _sendGroupMessage() {
        const text = this.el.groupInput?.value.trim();
        if (!text || !this.currentGroupId) return;
        this.el.groupInput.value = '';
        const msg = { msgId: this._genMsgId(), from: this.myName, content: text, ts: Date.now(), type: 'text', groupId: this.currentGroupId };
        const key = this._groupKey(this.currentGroupId);
        this._addMessage(key, msg);
        this._renderGroupMessages(this.currentGroupId);
        const group = this.myGroups.find(g => g.id === this.currentGroupId);
        if (group?.members) {
            for (const m of group.members) {
                if (m !== this.myName) {
                    FbAPI.sendSignal(this.token, m, 'group_msg', encodeURIComponent(JSON.stringify(msg))).catch(() => { });
                }
            }
        }
    }
    async _sendGroupFile(file) {
        if (!file || !this.currentGroupId) return;
        if (file.size > 5 * 1024 * 1024) { this.showNotification('エラー', 'ファイルは5MB以下にしてください', 'error'); return; }
        const reader = new FileReader();
        reader.onload = async e => {
            const msg = { msgId: this._genMsgId(), from: this.myName, content: '', ts: Date.now(), type: 'file', groupId: this.currentGroupId, file: { name: file.name, type: file.type, data: e.target.result } };
            const key = this._groupKey(this.currentGroupId);
            this._addMessage(key, msg);
            this._renderGroupMessages(this.currentGroupId);
            const group = this.myGroups.find(g => g.id === this.currentGroupId);
            if (group?.members) {
                for (const m of group.members) {
                    if (m !== this.myName) {
                        FbAPI.sendSignal(this.token, m, 'group_msg', encodeURIComponent(JSON.stringify(msg))).catch(() => { });
                    }
                }
            }
        };
        reader.readAsDataURL(file);
        if (this.el.groupFileInput) this.el.groupFileInput.value = '';
    }
    _receiveGroupMessage(groupId, fromName, msg) {
        const inGroup = this.myGroups.some(g => g.id === groupId);
        if (!inGroup) return;
        const key = this._groupKey(groupId);
        const added = this._addMessage(key, msg);
        if (!added) return; // 重複なら何もしない
        if (this.el.groupModal.classList.contains('visible') && this.currentGroupId === groupId) {
            // このグループを開いている → 既読扱い
            this._markAsRead(key);
            // 既読通知を全メンバーに送信
            this._sendReadReceiptForConv(key);
            this._renderGroupMessages(groupId);
            this._recomputeAllUnreadBadges();
        } else {
            // 開いていない → 未読として再計算してバッジ更新
            this._recomputeAllUnreadBadges();
            // グループ一覧が表示中なら一覧の未読バッジも更新
            if (this.el.groupModal.classList.contains('visible') && !this.currentGroupId) {
                this._renderGroupList();
            }
        }
    }
    _handleMemberLeft(groupId, memberName) {
        const group = this.myGroups.find(g => g.id === groupId);
        if (group?.members) group.members = group.members.filter(m => m !== memberName);
        if (this.currentGroupId === groupId) {
            const msg = { from: 'system', content: `${memberName} が退出しました`, ts: Date.now(), type: 'system' };
            this._addMessage(this._groupKey(groupId), msg);
            this._renderGroupMessages(groupId);
        }
    }
    _showGroupInvite(fromName, inv) {
        if (this.pendingGroupInvite) return;
        this.pendingGroupInvite = inv;
        if (this.el.groupInviteFrom) this.el.groupInviteFrom.textContent = fromName;
        if (this.el.groupInviteName) this.el.groupInviteName.textContent = inv.groupName || '';
        this.el.incomingGroupInviteModal.classList.add('visible');
    }
    async _handleGroupInvite(accept) {
        const inv = this.pendingGroupInvite;
        this.pendingGroupInvite = null;
        this.el.incomingGroupInviteModal.classList.remove('visible');
        if (accept && inv) {
            if (!this.myGroups.some(g => g.id === inv.groupId)) {
                this.myGroups.push({ id: inv.groupId, name: inv.groupName, members: [] });
                try { await this._loadGroups(); } catch (_) { }
            }
            this.showNotification('グループ', `「${inv.groupName}」に参加しました`, 'success');
        }
    }
    _updateGroupBadge() {
        const total = Object.values(this.groupUnreadCounts).reduce((a, b) => a + b, 0);
        if (this.el.groupBadge) {
            if (total > 0) {
                this.el.groupBadge.style.display = 'flex';
                this.el.groupBadge.textContent = total > 99 ? '99+' : total;
                this.el.groupBadge.classList.remove('badge-dot');
            } else if (this.activeGroupCalls && this.activeGroupCalls.size > 0 && !this._meshIsInCall?.()) {
                // 未読は無いが進行中の通話あり → ドット表示のみ
                // ただし自分が通話中（1対1含む）のときは表示しない（紛らわしくなるため）
                this.el.groupBadge.style.display = 'flex';
                this.el.groupBadge.textContent = '';
                this.el.groupBadge.classList.add('badge-dot');
            } else {
                this.el.groupBadge.style.display = 'none';
                this.el.groupBadge.textContent = '';
                this.el.groupBadge.classList.remove('badge-dot');
            }
        }
    }

    // =====================================================
    // ブロック機能
    // =====================================================
    _saveBlockedUsers() {
        localStorage.setItem('svc_blocked', JSON.stringify([...this.blockedUsers]));
    }
    _addBlock() {
        const name = this.el.blockSearchInput?.value.trim();
        if (this.el.blockError) this.el.blockError.textContent = '';
        if (!name) { if (this.el.blockError) this.el.blockError.textContent = '名前を入力してください'; return; }
        if (name === this.myName) { if (this.el.blockError) this.el.blockError.textContent = '自分はブロックできません'; return; }
        this.blockedUsers.add(name);
        this._saveBlockedUsers();
        if (this.el.blockSearchInput) this.el.blockSearchInput.value = '';
        this._renderBlockList();
        this.showNotification('ブロック', `${name} をブロックしました`, 'success');
    }
    _removeBlock(name) {
        this.blockedUsers.delete(name);
        this._saveBlockedUsers();
        this._renderBlockList();
    }
    _renderBlockList() {
        if (!this.el.blockList) return;
        if (this.blockedUsers.size === 0) {
            this.el.blockList.innerHTML = '<div class="friend-empty"><i class="fas fa-check-circle"></i><p>ブロック中のユーザーはいません</p></div>';
            return;
        }
        this.el.blockList.innerHTML = [...this.blockedUsers].map(name => `
            <div class="friend-item">
                <div class="friend-item-avatar" style="background:var(--danger-color)">${this.escapeHtml(name.charAt(0).toUpperCase())}</div>
                <span class="friend-item-name">${this.escapeHtml(name)}</span>
                <div class="friend-item-actions">
                    <button class="friend-remove-btn unblock-btn" data-name="${this.escapeHtml(name)}">
                        <i class="fas fa-unlock"></i> 解除
                    </button>
                </div>
            </div>`).join('');
        this.el.blockList.querySelectorAll('.unblock-btn').forEach(btn => {
            btn.addEventListener('click', () => this._removeBlock(btn.dataset.name));
        });
    }

    // =====================================================
    // メッセージバブル
    // =====================================================
    // =====================================================
    // アバター（プロフィール画像 / グループ画像）
    // =====================================================

    // 画像を 256x256 以内に縮小して JPEG 形式の dataURL を返す
    _resizeImageToDataUrl(file, maxSize = 256, quality = 0.85) {
        return new Promise((resolve, reject) => {
            if (!file || !file.type?.startsWith('image/')) {
                reject(new Error('画像ファイルを選択してください'));
                return;
            }
            const reader = new FileReader();
            reader.onload = e => {
                const img = new Image();
                img.onload = () => {
                    try {
                        let w = img.width, h = img.height;
                        // 中央を正方形にクロップ
                        const sz = Math.min(w, h);
                        const sx = (w - sz) / 2;
                        const sy = (h - sz) / 2;
                        const targetSize = Math.min(maxSize, sz);
                        const canvas = document.createElement('canvas');
                        canvas.width = targetSize;
                        canvas.height = targetSize;
                        const ctx = canvas.getContext('2d');
                        ctx.imageSmoothingEnabled = true;
                        ctx.imageSmoothingQuality = 'high';
                        ctx.drawImage(img, sx, sy, sz, sz, 0, 0, targetSize, targetSize);
                        // PNG透過があればPNG、それ以外はJPEGで容量削減
                        const out = canvas.toDataURL('image/jpeg', quality);
                        resolve(out);
                    } catch (err) { reject(err); }
                };
                img.onerror = () => reject(new Error('画像を読み込めませんでした'));
                img.src = e.target.result;
            };
            reader.onerror = () => reject(new Error('ファイル読み込みに失敗しました'));
            reader.readAsDataURL(file);
        });
    }

    // アバターキャッシュを localStorage に保存
    _saveAvatarCache() {
        try {
            // データ量が大きくなるので最大数を制限（直近100件）
            const entries = Object.entries(this.avatarCache);
            if (entries.length > 100) {
                const trimmed = Object.fromEntries(entries.slice(-100));
                this.avatarCache = trimmed;
            }
            localStorage.setItem('svc_avatar_cache', JSON.stringify(this.avatarCache));
        } catch (e) {
            // 容量超過時は古いキャッシュをクリア
            try { localStorage.removeItem('svc_avatar_cache'); } catch (_) { }
        }
    }

    // 名前のリストのアバターを取得してキャッシュに入れる
    async _fetchAvatarsFor(names) {
        const now = Date.now();
        const NULL_TTL = 60 * 1000; // null（画像未設定）は1分でリトライ
        // 未取得 or キャッシュがnullで時間が経っているもの
        const targets = [...new Set(names.filter(n => {
            if (!n) return false;
            if (!(n in this.avatarCache)) return true;
            if (this.avatarCache[n] === null) {
                const ts = this._avatarCacheTs?.[n] || 0;
                if ((now - ts) > NULL_TTL) return true;
            }
            return false;
        }))];
        if (targets.length === 0) return;
        // 連続呼び出しを抑制する: 取得中フラグ
        this._avatarFetching = this._avatarFetching || new Set();
        const newTargets = targets.filter(n => !this._avatarFetching.has(n));
        if (newTargets.length === 0) return;
        newTargets.forEach(n => this._avatarFetching.add(n));
        try {
            const res = await FbAPI.getUserAvatars(newTargets);
            if (!this._avatarCacheTs) this._avatarCacheTs = {};
            for (const n in res) {
                this.avatarCache[n] = res[n];
                this._avatarCacheTs[n] = Date.now();
            }
            this._saveAvatarCache();
        } catch (_) {
        } finally {
            newTargets.forEach(n => this._avatarFetching.delete(n));
        }
    }

    // アバターHTML生成（initial = 1文字、name = ユーザー名）
    // クラスは既存の avatar 系クラスを呼び出し側で指定
    _avatarStyleFor(name) {
        const url = this.avatarCache[name];
        if (url) return `background-image:url('${url}');background-size:cover;background-position:center`;
        return '';
    }

    // 既存の avatar 要素を画像で更新する（DOM内の全要素を一括）
    _refreshAvatarsInDom() {
        // ユーザーリスト、フレンドリスト、DM会話一覧、DM/グループのメッセージ全ての .user-avatar / .friend-item-avatar / .chat-msg-avatar
        const selectors = ['.user-avatar[data-uname]', '.friend-item-avatar[data-uname]', '.chat-msg-avatar[data-uname]'];
        selectors.forEach(sel => {
            document.querySelectorAll(sel).forEach(el => {
                const name = el.dataset.uname;
                if (!name) return;
                const url = this.avatarCache[name];
                if (url) {
                    el.classList.add('has-image');
                    el.style.backgroundImage = `url('${url}')`;
                } else {
                    el.classList.remove('has-image');
                    el.style.backgroundImage = '';
                }
            });
        });
        // グループアバター
        document.querySelectorAll('.friend-item-avatar[data-gid]').forEach(el => {
            const gid = el.dataset.gid;
            const url = this.groupAvatarCache[gid];
            if (url) {
                el.classList.add('has-image');
                el.style.backgroundImage = `url('${url}')`;
            } else {
                el.classList.remove('has-image');
                el.style.backgroundImage = '';
            }
        });
    }

    // 自分のアバターを読み込んで全UIに反映
    async _loadMyAvatar() {
        try {
            const url = await FbAPI.getUserAvatar(this.myName);
            this.myAvatar = url;
            this.avatarCache[this.myName] = url;
            this._saveAvatarCache();
            this._refreshAvatarsInDom();
            this._updateAvatarPreview();
        } catch (_) { }
    }

    // 設定モーダルのプレビュー更新
    _updateAvatarPreview() {
        if (!this.el.avatarPreview) return;
        const url = this.avatarCache[this.myName];
        if (url) {
            this.el.avatarPreview.classList.add('has-image');
            this.el.avatarPreview.style.backgroundImage = `url('${url}')`;
        } else {
            this.el.avatarPreview.classList.remove('has-image');
            this.el.avatarPreview.style.backgroundImage = '';
        }
        if (this.el.avatarPreviewInitial) {
            this.el.avatarPreviewInitial.textContent = (this.myName || '?').charAt(0).toUpperCase();
        }
    }

    async _onAvatarFileSelected(file) {
        if (!file) return;
        if (this.el.avatarError) this.el.avatarError.textContent = '';
        if (file.size > 10 * 1024 * 1024) {
            if (this.el.avatarError) this.el.avatarError.textContent = '10MB以下の画像を選択してください';
            return;
        }
        try {
            const dataUrl = await this._resizeImageToDataUrl(file, 256, 0.85);
            // データURLサイズ確認 (Firebase RTDB 単一文字列の現実的上限を意識して再縮小)
            let finalUrl = dataUrl;
            if (dataUrl.length > 200 * 1024) {
                finalUrl = await this._resizeImageToDataUrl(file, 192, 0.78);
            }
            const res = await FbAPI.setMyAvatar(this.token, finalUrl);
            if (res.ok) {
                this.myAvatar = finalUrl;
                this.avatarCache[this.myName] = finalUrl;
                this._saveAvatarCache();
                this._updateAvatarPreview();
                this._refreshAvatarsInDom();
                // 一覧系を再描画
                this._renderDmConversationList?.();
                this._renderGroupList?.();
                if (this._cachedFriendData) this._renderFriendModal();
                this.showNotification('プロフィール', 'プロフィール画像を更新しました', 'success');
            } else {
                if (this.el.avatarError) this.el.avatarError.textContent = res.error || '保存に失敗しました';
            }
        } catch (e) {
            if (this.el.avatarError) this.el.avatarError.textContent = e.message || '画像処理に失敗しました';
        }
        if (this.el.avatarFileInput) this.el.avatarFileInput.value = '';
    }

    async _removeMyAvatar() {
        if (this.el.avatarError) this.el.avatarError.textContent = '';
        try {
            const res = await FbAPI.setMyAvatar(this.token, null);
            if (res.ok) {
                this.myAvatar = null;
                this.avatarCache[this.myName] = null;
                this._saveAvatarCache();
                this._updateAvatarPreview();
                this._refreshAvatarsInDom();
                this._renderDmConversationList?.();
                this._renderGroupList?.();
                if (this._cachedFriendData) this._renderFriendModal();
                this.showNotification('プロフィール', 'プロフィール画像を削除しました', 'success');
            } else {
                if (this.el.avatarError) this.el.avatarError.textContent = res.error || '削除に失敗しました';
            }
        } catch (e) {
            if (this.el.avatarError) this.el.avatarError.textContent = 'サーバーへの接続に失敗しました';
        }
    }

    // --- 新規グループ作成時の画像選択 ---
    async _onNewGroupAvatarSelected(file) {
        if (!file) return;
        try {
            const dataUrl = await this._resizeImageToDataUrl(file, 256, 0.85);
            this._pendingNewGroupAvatar = dataUrl.length > 200 * 1024
                ? await this._resizeImageToDataUrl(file, 192, 0.78)
                : dataUrl;
            if (this.el.newGroupAvatarPreview) {
                this.el.newGroupAvatarPreview.classList.add('has-image');
                this.el.newGroupAvatarPreview.style.backgroundImage = `url('${this._pendingNewGroupAvatar}')`;
            }
        } catch (e) {
            this.showNotification('エラー', e.message || '画像処理に失敗しました', 'error');
        }
        if (this.el.newGroupAvatarInput) this.el.newGroupAvatarInput.value = '';
    }
    _clearNewGroupAvatar() {
        this._pendingNewGroupAvatar = null;
        if (this.el.newGroupAvatarPreview) {
            this.el.newGroupAvatarPreview.classList.remove('has-image');
            this.el.newGroupAvatarPreview.style.backgroundImage = '';
        }
        if (this.el.newGroupAvatarInput) this.el.newGroupAvatarInput.value = '';
    }

    // --- グループ設定モーダル ---
    _openGroupSettings() {
        if (!this.currentGroupId) return;
        const group = this.myGroups.find(g => g.id === this.currentGroupId);
        if (!group) return;
        const isOwner = (group.owner === this.myName);

        // 名前
        if (this.el.groupSettingsName) {
            this.el.groupSettingsName.value = group.name || '';
            this.el.groupSettingsName.disabled = !isOwner;
        }
        // 画像プレビュー
        const url = this.groupAvatarCache[group.id] || group.avatar || null;
        if (this.el.groupSettingsAvatarPreview) {
            if (url) {
                this.el.groupSettingsAvatarPreview.classList.add('has-image');
                this.el.groupSettingsAvatarPreview.style.backgroundImage = `url('${url}')`;
            } else {
                this.el.groupSettingsAvatarPreview.classList.remove('has-image');
                this.el.groupSettingsAvatarPreview.style.backgroundImage = '';
            }
        }
        // オーナー以外は編集ボタンを無効化
        if (this.el.groupSettingsAvatarUploadLabel) {
            this.el.groupSettingsAvatarUploadLabel.style.opacity = isOwner ? '1' : '0.4';
            this.el.groupSettingsAvatarUploadLabel.style.pointerEvents = isOwner ? '' : 'none';
        }
        if (this.el.groupSettingsAvatarRemoveBtn) {
            this.el.groupSettingsAvatarRemoveBtn.disabled = !isOwner;
            this.el.groupSettingsAvatarRemoveBtn.style.opacity = isOwner ? '1' : '0.4';
        }
        if (this.el.groupSettingsSaveBtn) {
            this.el.groupSettingsSaveBtn.disabled = !isOwner;
            this.el.groupSettingsSaveBtn.style.opacity = isOwner ? '1' : '0.4';
        }
        if (this.el.groupSettingsHint) {
            this.el.groupSettingsHint.textContent = isOwner
                ? 'グループ画像と名前を変更できます。'
                : 'グループのオーナーのみ画像と名前を変更できます。';
        }
        if (this.el.groupSettingsError) this.el.groupSettingsError.textContent = '';
        this._pendingGroupAvatarChange = undefined; // 未変更
        this.el.groupSettingsModal.classList.add('visible');
    }

    async _onGroupSettingsAvatarSelected(file) {
        if (!file) return;
        const group = this.myGroups.find(g => g.id === this.currentGroupId);
        if (!group || group.owner !== this.myName) return;
        try {
            const dataUrl = await this._resizeImageToDataUrl(file, 256, 0.85);
            const finalUrl = dataUrl.length > 200 * 1024
                ? await this._resizeImageToDataUrl(file, 192, 0.78)
                : dataUrl;
            this._pendingGroupAvatarChange = finalUrl;
            if (this.el.groupSettingsAvatarPreview) {
                this.el.groupSettingsAvatarPreview.classList.add('has-image');
                this.el.groupSettingsAvatarPreview.style.backgroundImage = `url('${finalUrl}')`;
            }
        } catch (e) {
            if (this.el.groupSettingsError) this.el.groupSettingsError.textContent = e.message || '画像処理に失敗しました';
        }
        if (this.el.groupSettingsAvatarInput) this.el.groupSettingsAvatarInput.value = '';
    }

    _clearGroupSettingsAvatar() {
        const group = this.myGroups.find(g => g.id === this.currentGroupId);
        if (!group || group.owner !== this.myName) return;
        this._pendingGroupAvatarChange = null;
        if (this.el.groupSettingsAvatarPreview) {
            this.el.groupSettingsAvatarPreview.classList.remove('has-image');
            this.el.groupSettingsAvatarPreview.style.backgroundImage = '';
        }
    }

    async _saveGroupSettings() {
        if (!this.currentGroupId) return;
        const group = this.myGroups.find(g => g.id === this.currentGroupId);
        if (!group) return;
        if (group.owner !== this.myName) return;
        if (this.el.groupSettingsError) this.el.groupSettingsError.textContent = '';

        const newName = this.el.groupSettingsName?.value.trim() || '';
        if (!newName) {
            if (this.el.groupSettingsError) this.el.groupSettingsError.textContent = 'グループ名を入力してください';
            return;
        }

        const btn = this.el.groupSettingsSaveBtn;
        const origHtml = btn?.innerHTML;
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 保存中...'; }
        try {
            // 名前変更
            if (newName !== group.name) {
                const res = await FbAPI.updateGroupName(this.token, this.currentGroupId, newName);
                if (!res.ok) {
                    if (this.el.groupSettingsError) this.el.groupSettingsError.textContent = res.error || '名前変更に失敗しました';
                    if (btn) { btn.disabled = false; btn.innerHTML = origHtml; }
                    return;
                }
                group.name = newName;
                this.currentGroupName = newName;
                if (this.el.groupChatName) this.el.groupChatName.textContent = newName;
            }
            // アバター変更（pending が undefined なら未変更）
            if (this._pendingGroupAvatarChange !== undefined) {
                const res = await FbAPI.updateGroupAvatar(this.token, this.currentGroupId, this._pendingGroupAvatarChange);
                if (!res.ok) {
                    if (this.el.groupSettingsError) this.el.groupSettingsError.textContent = res.error || '画像変更に失敗しました';
                    if (btn) { btn.disabled = false; btn.innerHTML = origHtml; }
                    return;
                }
                group.avatar = this._pendingGroupAvatarChange;
                this.groupAvatarCache[this.currentGroupId] = this._pendingGroupAvatarChange;
            }
            this._pendingGroupAvatarChange = undefined;
            this.el.groupSettingsModal.classList.remove('visible');
            this._renderGroupList?.();
            this._refreshAvatarsInDom();
            this.showNotification('グループ', 'グループ設定を保存しました', 'success');
        } catch (e) {
            if (this.el.groupSettingsError) this.el.groupSettingsError.textContent = 'サーバーへの接続に失敗しました';
        }
        if (btn) { btn.disabled = false; btn.innerHTML = origHtml; }
    }

    _renderMessageBubble(msg, ctx) {
        const isMine = msg.from === this.myName;
        const time = msg.ts ? new Date(msg.ts).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }) : '';
        if (msg.type === 'system') {
            return `<div class="chat-msg-system">${this.escapeHtml(msg.content)}</div>`;
        }
        // 管理者からの一斉お知らせ（特別表示）
        if (msg.type === 'admin_broadcast') {
            const dateStr = msg.ts ? new Date(msg.ts).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
            return `<div class="chat-msg-admin">
                <div class="chat-msg-admin-header">
                    <i class="fas fa-bullhorn"></i>
                    管理者からのお知らせ
                </div>
                <div class="chat-msg-admin-body">${this.escapeHtml(msg.content || '')}</div>
                <div class="chat-msg-admin-time">${dateStr}</div>
            </div>`;
        }
        let contentHtml = '';
        let bubbleClass = 'chat-msg-bubble';
        if (msg.recalled === true) {
            // 取り消し済みメッセージ
            bubbleClass += ' recalled';
            const txt = isMine ? 'あなたがメッセージを取り消しました' : 'メッセージが取り消されました';
            contentHtml = `<span><i class="fas fa-rotate-left recalled-icon"></i>${this.escapeHtml(txt)}</span>`;
        } else if (msg.type === 'file' && msg.file) {
            const f = msg.file;
            if (f._dropped || !f.data) {
                // 端末容量の都合でファイル本体が削られたケース
                contentHtml = `<span class="chat-file-dropped"><i class="fas fa-file"></i> ${this.escapeHtml(f.name || 'ファイル')} <small>(端末では非保持)</small></span>`;
            } else if (f.type?.startsWith('image/')) {
                contentHtml = `<img src="${f.data}" alt="${this.escapeHtml(f.name)}" class="chat-img-preview" onclick="this.requestFullscreen?.()">`;
            } else if (f.type?.startsWith('video/')) {
                contentHtml = `<video src="${f.data}" controls class="chat-img-preview"></video>`;
            } else {
                contentHtml = `<a href="${f.data}" download="${this.escapeHtml(f.name)}" class="chat-file-link"><i class="fas fa-file"></i> ${this.escapeHtml(f.name)}</a>`;
            }
        } else {
            contentHtml = `<span>${this.escapeHtml(msg.content || '')}</span>`;
        }
        let avatarHtml = '';
        if (!isMine) {
            const fromName = msg.from || '?';
            const avUrl = this.avatarCache[fromName];
            if (avUrl) {
                avatarHtml = `<div class="chat-msg-avatar has-image" data-uname="${this.escapeHtml(fromName)}" style="background-image:url('${avUrl}')"></div>`;
            } else {
                avatarHtml = `<div class="chat-msg-avatar" data-uname="${this.escapeHtml(fromName)}">${this.escapeHtml(fromName.charAt(0).toUpperCase())}</div>`;
                // バックグラウンド取得（_fetchAvatarsFor内でデバウンス・キャッシュTTL判定）
                this._fetchAvatarsFor([fromName]).then(() => this._refreshAvatarsInDom());
            }
        }
        // 自分が送ったメッセージにだけ既読表示（取り消し済みは出さない）
        let readReceiptHtml = '';
        if (isMine && ctx && !msg.recalled) {
            const readBy = Array.isArray(msg.readBy) ? msg.readBy.filter(n => n !== this.myName) : [];
            if (ctx.type === 'dm') {
                // DM: 相手が読んでいたら「既読」
                if (readBy.length > 0) {
                    readReceiptHtml = `<div class="chat-msg-readreceipt">既読</div>`;
                }
            } else if (ctx.type === 'group') {
                // グループ: 既読人数（自分以外のメンバー数を超えないようにクランプ）
                const otherMembers = (ctx.memberCount || 1) - 1;
                const seenCount = Math.min(readBy.length, Math.max(otherMembers, 0));
                if (seenCount > 0) {
                    readReceiptHtml = `<div class="chat-msg-readreceipt">既読 ${seenCount}</div>`;
                }
            }
        }
        const msgIdAttr = msg.msgId ? ` data-msgid="${this.escapeHtml(msg.msgId)}"` : '';
        const ctxTypeAttr = ctx?.type ? ` data-ctxtype="${this.escapeHtml(ctx.type)}"` : '';
        const ctxKeyAttr = ctx?.type === 'dm' && ctx.partner
            ? ` data-ctxkey="${this.escapeHtml(ctx.partner)}"`
            : (ctx?.type === 'group' && ctx.groupId ? ` data-ctxkey="${this.escapeHtml(ctx.groupId)}"` : '');
        return `<div class="chat-msg ${isMine ? 'mine' : 'theirs'}"${msgIdAttr}${ctxTypeAttr}${ctxKeyAttr}>
            ${avatarHtml}
            <div class="chat-msg-body">
                ${!isMine ? `<div class="chat-msg-name">${this.escapeHtml(msg.from || '')}</div>` : ''}
                <div class="${bubbleClass}">${contentHtml}</div>
                <div class="chat-msg-time">${time}</div>
                ${readReceiptHtml}
            </div>
        </div>`;
    }

    // =====================================================
    // 音声・映像制御
    // =====================================================
    toggleAudio() {
        // メッシュ通話中ならメッシュ用に分岐
        if (this._meshIsInCall && this._meshIsInCall()) {
            return this._meshToggleMic();
        }
        // 待機状態（通話前のプレビュー）：旧式のフラグも更新しておく（次回通話の初期値に反映）
        this.isAudioEnabled = !this.isAudioEnabled;
        this.meshMicOn = this.isAudioEnabled;
        if (this.localStream) this.localStream.getAudioTracks().forEach(t => t.enabled = this.isAudioEnabled);
        this._syncMediaButtonsUI();
    }

    toggleVideo() {
        if (this._meshIsInCall && this._meshIsInCall()) {
            return this._meshToggleCam();
        }
        // 画面共有中はカメラON/OFFトグルを無効化
        if (this.isScreenSharing) {
            this.showNotification('通知', '画面共有中はカメラを切り替えられません', 'warning');
            return;
        }
        this.isVideoEnabled = !this.isVideoEnabled;
        this.meshCamOn = this.isVideoEnabled;
        if (this.localStream) this.localStream.getVideoTracks().forEach(t => t.enabled = this.isVideoEnabled);
        this._syncMediaButtonsUI();
        this._updateLocalAvatarOverlay();
    }

    // 自分のカメラ/画面共有状態を相手に通知
    async _sendMediaStateToPeer() {
        if (!this.dataConnection || this.dataConnection.open === false) return;
        const payload = {
            type: 'MEDIA_STATE',
            videoOn: this.isVideoEnabled,
            screenSharing: this.isScreenSharing,
            // アバター表示用に自分の名前も送る（受信側は avatarCache から URL を引く）
            from: this.myName
        };
        try {
            if (this.encryptionKey) {
                const enc = await CryptoUtil.encrypt(this.encryptionKey, new TextEncoder().encode(JSON.stringify(payload)));
                this.dataConnection.send({ iv: enc.iv, encryptedData: enc.encryptedData });
            } else {
                this.dataConnection.send(payload);
            }
        } catch (e) {
            console.warn('media state 送信失敗:', e);
        }
    }

    // 自分のカメラOFF時、ローカル映像にアバターオーバーレイを出す
    _updateLocalAvatarOverlay() {
        if (!this.el.localAvatarOverlay) return;
        // 画面共有中はオーバーレイ非表示
        const showOverlay = !this.isVideoEnabled && !this.isScreenSharing;
        this.el.localAvatarOverlay.style.display = showOverlay ? '' : 'none';
        if (showOverlay) {
            this._renderAvatarCircle(this.el.localAvatarCircle, this.el.localAvatarInitial, this.myName);
        }
    }

    // 相手のカメラOFF時、リモート映像にアバターオーバーレイを出す
    _updateRemoteAvatarOverlay() {
        if (!this.el.remoteAvatarOverlay) return;
        const partner = this.callTargetName || this.el.remoteName?.textContent || '';
        // 通話中で、相手のカメラがOFFのとき表示
        const showOverlay = !!this.currentCall && this.remoteCameraOff === true;
        this.el.remoteAvatarOverlay.style.display = showOverlay ? '' : 'none';
        if (showOverlay && partner) {
            this._renderAvatarCircle(this.el.remoteAvatarCircle, this.el.remoteAvatarInitial, partner);
            // キャッシュにまだ無ければ取得
            if (!this.avatarCache[partner]) {
                this._fetchAvatarsFor([partner]).then(() => {
                    if (this.remoteCameraOff && this.currentCall) {
                        this._renderAvatarCircle(this.el.remoteAvatarCircle, this.el.remoteAvatarInitial, partner);
                    }
                });
            }
        }
    }

    _renderAvatarCircle(circleEl, initialEl, name) {
        if (!circleEl) return;
        const avUrl = name ? this.avatarCache[name] : null;
        if (avUrl) {
            circleEl.classList.add('has-image');
            circleEl.style.backgroundImage = `url('${avUrl}')`;
            if (initialEl) initialEl.textContent = '';
        } else {
            circleEl.classList.remove('has-image');
            circleEl.style.backgroundImage = '';
            if (initialEl) initialEl.textContent = (name || '?').charAt(0).toUpperCase();
        }
    }

    // =====================================================
    // 画面共有
    // =====================================================
    async toggleScreenShare() {
        if (this._meshIsInCall && this._meshIsInCall()) {
            return this._meshToggleScreenShare();
        }
        this.showNotification('通知', '通話中のみ画面共有できます', 'warning');
    }

    async _startScreenShare() {
        // 旧1対1WebRTC用。メッシュ通話では _meshStartScreenShare を使う
        console.warn('[deprecated] _startScreenShare called. Use _meshStartScreenShare instead.');
    }

    async _stopScreenShare(isCallEnding = false) {
        // 旧1対1WebRTC用。メッシュ通話では _meshStopScreenShare を使う
        console.warn('[deprecated] _stopScreenShare called. Use _meshStopScreenShare instead.');
    }

    toggleVolumeControl() {
        this.isVolumeControlVisible = !this.isVolumeControlVisible;
        this.el.volumeSliderContainer.classList.toggle('visible', this.isVolumeControlVisible);
    }

    setupAudioBoost(stream) {
        try {
            // 古いコンテキストが残っていれば閉じる
            if (this.audioContext) {
                try { this.audioContext.close(); } catch (_) { }
            }
            this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            this.audioSource = this.audioContext.createMediaStreamSource(stream);

            // === 多段増幅チェーン ===
            // [source] → preGain → compressor → makeUpGain → destination
            // preGain: 入力を素直に増幅（最大10倍程度まで可能）
            // compressor: 大音量で歪まないように圧縮（聞こえやすさUP）
            // makeUpGain: 圧縮後さらに底上げ
            this.preGainNode = this.audioContext.createGain();
            this.compressorNode = this.audioContext.createDynamicsCompressor();
            // 強めの圧縮設定でラウドネス感を稼ぐ
            this.compressorNode.threshold.value = -28; // dB（これを超えると圧縮）
            this.compressorNode.knee.value = 18;       // dB（ソフトニー）
            this.compressorNode.ratio.value = 6;       // 6:1 圧縮
            this.compressorNode.attack.value = 0.003;  // 速いアタック
            this.compressorNode.release.value = 0.15;  // やや早めのリリース
            this.makeUpGainNode = this.audioContext.createGain();
            this.makeUpGainNode.gain.value = 1.8;      // 圧縮後の補正ゲイン

            // 後方互換: 既存コードが参照する gainNode は preGainNode を指す
            this.gainNode = this.preGainNode;

            this.audioSource.connect(this.preGainNode);
            this.preGainNode.connect(this.compressorNode);
            this.compressorNode.connect(this.makeUpGainNode);
            this.makeUpGainNode.connect(this.audioContext.destination);

            // currentVolumeに従ってpreGainNodeのgainを設定
            this._applyVolumeGain(this.currentVolume);

            this.el.remoteVideo.muted = true;

            // スライダーUIも現在値で再描画（前回の通話の値が引き継がれていてもバーが正しく見えるように）
            if (this.el.volumeSlider) {
                this.el.volumeSlider.value = this.currentVolume;
            }
            this._refreshVolumeUI(this.currentVolume);
        } catch (e) { console.warn('WebAudio初期化失敗:', e); }
    }

    // value(%) → preGainNode.gain.value を計算して反映
    _applyVolumeGain(value) {
        let v = parseInt(value) || 0;
        // 0–100%にクランプ
        if (v < 0) v = 0;
        if (v > 100) v = 100;
        // 0–100%: 通常のリニアゲイン（0.0 – 1.0）
        const gain = v / 100;
        if (this.preGainNode) {
            this.preGainNode.gain.value = gain;
        } else if (this.el.remoteVideo) {
            this.el.remoteVideo.volume = Math.min(gain, 1);
        }
    }

    updateVolume(value) {
        this.currentVolume = parseInt(value);
        this._applyVolumeGain(this.currentVolume);
        this._refreshVolumeUI(this.currentVolume);
    }

    // 音量UI（バーの色、アイコン、数値）を更新する
    // currentVolume が変わったとき / setupAudioBoost で再表示するときに呼ぶ
    _refreshVolumeUI(value) {
        let v = parseInt(value);
        if (v > 100) v = 100;
        if (v < 0) v = 0;
        if (!this.el.volumeControlButton) return;
        const icon = this.el.volumeControlButton.querySelector('i');
        if (icon) {
            if (v == 0) icon.className = 'fas fa-volume-mute';
            else if (v < 50) icon.className = 'fas fa-volume-down';
            else icon.className = 'fas fa-volume-up';
        }
        const MAX = 100;
        const pct = (v / MAX) * 100;
        const bg = `linear-gradient(to right, rgba(255,255,255,0.8) ${pct}%, rgba(255,255,255,0.2) ${pct}%)`;
        if (this.el.volumeSlider) {
            this.el.volumeSlider.style.background = bg;
            this.el.volumeSlider.classList.remove('boosted');
        }
        if (this.el.volumeValue) this.el.volumeValue.textContent = v;
        if (this.el.boostBadge) this.el.boostBadge.classList.remove('visible');
    }

    startConnectionQualityMonitoring() {
        if (this._qualityInterval) {
            clearInterval(this._qualityInterval);
        }
        this._qualityInterval = setInterval(() => {
            if (!this.currentCall?.peerConnection) {
                clearInterval(this._qualityInterval);
                this._qualityInterval = null;
                return;
            }
            this.currentCall.peerConnection.getStats().then(stats => {
                stats.forEach(r => {
                    if (r.type === 'candidate-pair' && r.state === 'succeeded') {
                        this.el.connectionQuality.textContent = this.calcQuality(r);
                    }
                });
            });
        }, 2000);
    }

    calcQuality(stats) {
        if (stats.availableOutgoingBitrate) {
            const bps = stats.availableOutgoingBitrate / 1000000;
            if (bps > 2) return '良好';
            if (bps > 1) return '普通';
            return '不安定';
        }
        return '計測中...';
    }

    updateConnectionQuality(state) {
        const map = { new: '接続確認中...', checking: '接続確認中...', connected: '良好', completed: '安定', disconnected: '切断', failed: '接続失敗' };
        this.el.connectionQuality.textContent = map[state] || '不明';
    }

    updateStatus(message, isError = false) {
        if (this.el.connectionStatus) this.el.connectionStatus.textContent = message;
        if (this.el.statusIndicator) this.el.statusIndicator.classList.toggle('connected', !isError && message === 'オンライン' || message === '通話中');
    }

    showNotification(title, message, type = 'info') {
        const modal = this.el.notificationModal;
        const msgEl = modal.querySelector('.modal-message');
        const iconEl = modal.querySelector('.modal-icon');
        msgEl.textContent = message;
        iconEl.className = 'modal-icon fas';
        const icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', warning: 'fa-exclamation-triangle', info: 'fa-info-circle' };
        iconEl.classList.add(icons[type] || 'fa-info-circle');
        const colors = { success: 'var(--success-color)', error: 'var(--danger-color)', warning: 'var(--warning-color)', info: 'var(--primary-color)' };
        iconEl.style.color = colors[type] || 'var(--primary-color)';
        // DOMの最後に移動して必ず最前面に表示
        if (modal.parentNode !== document.body || modal !== document.body.lastElementChild) {
            document.body.appendChild(modal);
        }
        modal.style.zIndex = '9999';
        modal.classList.add('visible');
    }

    showDisconnectOverlay(reason = '通話が終了しました') {
        const existing = document.getElementById('disconnectOverlay');
        if (existing) return;
        const overlay = document.createElement('div');
        overlay.id = 'disconnectOverlay';
        overlay.className = 'disconnect-overlay';
        overlay.innerHTML = `
            <div class="disconnect-overlay-content">
                <div class="disconnect-icon"><i class="fas fa-phone-slash"></i></div>
                <p class="disconnect-reason">${this.escapeHtml(reason)}</p>
                <p class="disconnect-sub">接続が切断されました</p>
                <button class="disconnect-close-btn" onclick="document.getElementById('disconnectOverlay').remove()">閉じる</button>
            </div>`;
        document.body.appendChild(overlay);
        setTimeout(() => {
            if (overlay.parentNode) {
                overlay.classList.add('fade-out');
                setTimeout(() => overlay.remove(), 400);
            }
        }, 5000);
    }

    onBeforeUnload() {
        this.isDisconnecting = true;
        if (this.dataConnection?.open !== false) {
            try { this.dataConnection.send({ type: 'DISCONNECT_SIGNAL' }); } catch (_) { }
        }
        // sendBeaconの代わりに、可能な範囲でFirebaseへ同期的に削除リクエスト
        // ブラウザを閉じる際は onDisconnect で自動的に presence が削除される
        if (this.token) {
            try { FbAPI.logout(this.token); } catch (_) { }
        }
        // ページ離脱時は確実にメディアトラックを停止
        if (this.localStream) {
            try { this.localStream.getTracks().forEach(t => t.stop()); } catch (_) { }
            this.localStream = null;
        }
        // メッシュ通話中ならbye送信
        try { this._meshBroadcastBye(); } catch (_) { }
        if (this.meshPeer) { try { this.meshPeer.destroy(); } catch (_) { } }
        this.cleanup();
    }

    // ============================================================
    // ============================================================
    //                    メッシュ通話機能
    //   通話以外はFirebase、通話はPeerJSフルメッシュで行う
    //   ホストPeerID = meshcall-{ホスト本名}-host
    //   参加者PeerID = meshcall-{ホスト本名}-{ランダム}
    //   roomId = ホストの本名 そのまま
    // ============================================================
    // ============================================================

    // --- 状態初期化（コンストラクタで呼ばれていない分の補完。重複しても害なし） ---
    _meshEnsureStateInit() {
        if (!this.meshPeers) this.meshPeers = new Map();
        if (!this.outgoingMeshInvitees) this.outgoingMeshInvitees = new Set();
        if (typeof this.meshIsHost !== 'boolean') this.meshIsHost = false;
        if (typeof this.meshMicOn !== 'boolean') this.meshMicOn = true;
        if (typeof this.meshCamOn !== 'boolean') this.meshCamOn = false; // カメラOFFスタート
        if (typeof this.meshIsScreenSharing !== 'boolean') this.meshIsScreenSharing = false;
        if (!this.meshSavedCameraTrack) this.meshSavedCameraTrack = null;
        if (!this.meshGroupId) this.meshGroupId = null; // グループ通話の場合のグループID
    }

    _meshLog(...args) { console.log('[mesh]', ...args); }

    // --- メッシュ通話中かどうか ---
    _meshIsInCall() {
        return !!this.meshPeer;
    }

    // ====================================================
    // メッシュ用 localStream
    // ====================================================
    async _ensureMeshLocalStream() {
        // 既存の this.localStream を流用する。なければ新規取得。
        if (this.localStream) {
            const tracks = this.localStream.getTracks();
            const allActive = tracks.length > 0 && tracks.every(t => t.readyState === 'live');
            if (allActive) {
                // 状態を反映
                this.localStream.getAudioTracks().forEach(t => t.enabled = this.meshMicOn);
                this.localStream.getVideoTracks().forEach(t => t.enabled = this.meshCamOn);
                return this.localStream;
            }
        }
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
            this.localStream.getVideoTracks().forEach(t => t.enabled = this.meshCamOn);
            this.localStream.getAudioTracks().forEach(t => t.enabled = this.meshMicOn);
            this.isMediaReady = true;
        } catch (e) {
            console.warn('[mesh] カメラ/マイク取得失敗。音声のみで再試行:', e);
            try {
                this.localStream = await navigator.mediaDevices.getUserMedia({ video: false, audio: true });
                this.localStream.getAudioTracks().forEach(t => t.enabled = this.meshMicOn);
                this.meshCamOn = false;
                this.isMediaReady = true;
            } catch (e2) {
                this.localStream = null;
                this.isMediaReady = false;
                throw e2;
            }
        }
        return this.localStream;
    }

    // ====================================================
    // メッシュPeer 起動
    // ====================================================
    // _meshInitPeer(roomId, isHost, options?)
    //   options.isGroupCall: グループ通話の場合 true
    //   options.groupId: グループID（グループ通話のとき）
    //   グループ通話の場合、ホストPeerIDも meshcall-grp-{groupId}-{ランダム} とすることで
    //   ホスト交代時のPeerJS unavailable-id 問題を回避する
    _meshInitPeer(roomId, isHost, options = {}) {
        return new Promise((resolve, reject) => {
            let myMeshPeerId;
            if (options.isGroupCall && options.groupId) {
                // グループ通話: ホストも参加者もランダムサフィックス付き
                // groupId はサニタイズして使用
                const rand = Math.random().toString(36).slice(2, 10);
                myMeshPeerId = `meshcall-grp-${this._meshSanitize(options.groupId)}-${rand}`;
            } else {
                // 1対1通話: 旧仕様（ホスト = -host、参加者 = ランダム）
                myMeshPeerId = isHost
                    ? `meshcall-${this._meshSanitize(roomId)}-host`
                    : `meshcall-${this._meshSanitize(roomId)}-${Math.random().toString(36).slice(2, 8)}`;
            }
            const peer = new Peer(myMeshPeerId, {
                config: {
                    iceServers: [
                        { urls: 'stun:stun.l.google.com:19302' },
                        { urls: 'stun:stun1.google.com:19302' },
                    ]
                },
                secure: true,
                debug: 1
            });

            let resolved = false;
            peer.on('open', id => {
                this.meshPeer = peer;
                this.meshMyId = id;
                resolved = true;
                resolve(peer);
            });

            peer.on('error', err => {
                console.error('[mesh] peer error:', err);
                if (err.type === 'unavailable-id') {
                    if (!resolved) {
                        reject(new Error('PeerID衝突。再試行してください'));
                    }
                    return;
                }
                if (err.type === 'peer-unavailable') {
                    // 相手が居なくなっただけ。スルー
                    return;
                }
                if (!resolved) {
                    reject(new Error('メッシュ通話の接続に失敗しました: ' + err.type));
                }
            });

            peer.on('call', call => {
                call.answer(this.localStream);
                this._meshHandleIncomingCall(call);
            });

            peer.on('connection', conn => {
                this._meshSetupDataConnection(conn);
            });

            peer.on('disconnected', () => {
                this._meshLog('peer disconnected, attempting reconnect');
                setTimeout(() => { try { peer.reconnect(); } catch (_) { } }, 2000);
            });

            setTimeout(() => {
                if (!resolved) reject(new Error('シグナリングサーバ接続タイムアウト'));
            }, 15000);
        });
    }

    // ルームID（=ホスト本名）に使えるようサニタイズ（PeerJSのIDに使える文字）
    _meshSanitize(s) {
        // 日本語/記号も含む本名をbase16でエンコード（PeerJSのID制約は割と緩いが、安全側）
        try {
            const enc = new TextEncoder().encode(String(s));
            return Array.from(enc).map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (_) {
            return String(s).replace(/[^a-zA-Z0-9]/g, '');
        }
    }

    // ====================================================
    // 入退室
    // ====================================================
    // hostName はホストの本名、isHost = 自分がホストかどうか
    // groupContext = { groupId, groupName, hostPeerId? } （グループ通話の場合）
    //   hostPeerId: 参加者の場合は Firebase から取得した既存ホストPeerID（必須）
    async _startMeshCall({ hostName, isHost, groupContext = null }) {
        if (this._meshIsInCall()) {
            this.showNotification('通知', '既に通話中です', 'warning');
            return false;
        }
        this._meshEnsureStateInit();
        this.meshRoomId = hostName;
        this.meshHostName = hostName;
        this.meshIsHost = !!isHost;
        this.meshGroupId = groupContext?.groupId || null;
        this.meshGroupName = groupContext?.groupName || null;
        this.callTargetName = isHost ? null : hostName; // 既存UI互換

        this.updateStatus('カメラ・マイク準備中...');
        try {
            await this._ensureMeshLocalStream();
        } catch (e) {
            this.showNotification('通知', 'カメラ/マイクの利用が拒否されました。音声・映像なしで通話します。', 'warning');
        }

        this.updateStatus('通話の準備中...');
        try {
            await this._meshInitPeer(hostName, isHost, {
                isGroupCall: !!this.meshGroupId,
                groupId: this.meshGroupId
            });
        } catch (e) {
            this.showNotification('エラー', e.message || 'メッシュ通話の開始に失敗しました', 'error');
            this._meshClearState();
            return false;
        }

        // ホストとして起動した場合 + グループ通話なら Firebase に自分のPeerIDを登録
        if (isHost && this.meshGroupId) {
            try {
                const setRes = await FbAPI.setGroupActiveCall(this.token, this.meshGroupId, this.myName, this.meshMyId);
                if (setRes && setRes.ok) {
                    // 自分が切断されたら自動で activeCall を削除する予約
                    await FbAPI.setupActiveCallOnDisconnect(this.meshGroupId);
                } else {
                    console.warn('[mesh] setGroupActiveCall not ok:', setRes);
                }
            } catch (e) {
                console.warn('[mesh] setGroupActiveCall failed:', e);
            }
        }

        // 画面切り替え
        this._meshEnterUI();

        // 自分のタイル
        this._meshEnsureTile(this.meshMyId, true, this.myName);
        this._meshSetTileStream(this.meshMyId, this.localStream);
        this._meshSetTileStatus(this.meshMyId, this.meshMicOn, this.meshCamOn);

        if (!isHost) {
            // ホストに接続
            this.updateStatus('ホストに接続中...');
            // グループ通話の場合: Firebaseから取得したhostPeerIdを使う
            // 1対1通話の場合: meshcall-{ホスト本名}-host
            let hostMeshId;
            if (this.meshGroupId && groupContext?.hostPeerId) {
                hostMeshId = groupContext.hostPeerId;
            } else {
                hostMeshId = `meshcall-${this._meshSanitize(hostName)}-host`;
            }
            this._meshTargetHostPeerId = hostMeshId;
            // 接続とリトライ
            this._meshHostConnectAttempt = 0;
            setTimeout(() => this._meshTryConnectHost(hostMeshId), 500);
        } else {
            // ホスト側初期ステータス: グループ通話か1対1で文言を変える
            if (this.meshGroupId) {
                this.updateStatus('待機中 - メンバーの参加を待っています');
            } else {
                this.updateStatus('待機中 - 招待してください');
            }
        }

        return true;
    }

    // ホストへの接続を試行（タイムアウト時にリトライ）
    async _meshTryConnectHost(hostPeerId) {
        if (!this._meshIsInCall()) return;
        // 既に接続済み（helloを受け取り済み）なら何もしない
        const existing = this.meshPeers.get(hostPeerId);
        if (existing && existing.name && existing.name !== '...') {
            // 既にホストとhelloまで完了している
            return;
        }
        this._meshHostConnectAttempt = (this._meshHostConnectAttempt || 0) + 1;
        this._meshLog(`ホスト接続試行 #${this._meshHostConnectAttempt}: ${hostPeerId}`);

        // 接続を試みる
        this._meshConnectToPeer(hostPeerId);

        // 2回目以降のリトライならユーザーに通知
        if (this._meshHostConnectAttempt === 2) {
            this.showNotification('通話', 'ホストが交代されたため、接続に少し時間がかかります...', 'info', 3500);
            this.updateStatus('ホスト交代中 - 接続再試行中...');
        }

        // 4秒待って、まだ接続が確立されていなければリトライ（旧7秒→4秒に短縮で体感速度向上）
        clearTimeout(this._meshHostConnectTimeoutId);
        this._meshHostConnectTimeoutId = setTimeout(async () => {
            if (!this._meshIsInCall()) return;
            // 既に接続済みなら何もしない
            const cur = this.meshPeers.get(hostPeerId);
            if (cur && cur.name && cur.name !== '...') return;

            // 既存の不完全な接続をクリーンアップ
            this._meshLog(`ホスト接続タイムアウト: ${hostPeerId}`);
            if (cur) {
                if (cur.call) { try { cur.call.close(); } catch (_) { } }
                if (cur.conn) { try { cur.conn.close(); } catch (_) { } }
                this.meshPeers.delete(hostPeerId);
                this._meshRemoveTile(hostPeerId);
            }

            if (this._meshHostConnectAttempt >= 4) {
                // 4回試行してもダメ → ゾンビ通話と判断（旧3回→4回に増加、合計約16秒）
                this._meshLog('ホストへの接続に4回失敗。ゾンビ通話の可能性あり');

                // グループ通話の場合は自動回復: 強制クリア → 自分が新ホストとして引き継ぐ
                if (this.meshGroupId) {
                    const groupId = this.meshGroupId;
                    const groupName = this.meshGroupName;

                    // 現在の通話状態を一度終了
                    this._meshLog('ゾンビ通話を強制クリアして自分が新ホストとして開始します');
                    try { await FbAPI.forceClearGroupActiveCall(this.token, groupId); } catch (_) { }

                    // 通話状態をリセット（_leaveMeshCallの軽量版）
                    if (this.meshPeer) {
                        try { this.meshPeer.destroy(); } catch (_) { }
                        this.meshPeer = null;
                    }
                    this.meshPeers.clear();
                    this.meshMyId = null;
                    this._meshClearState();

                    // 少し待つ（PeerJSサーバー側のID解放）
                    await new Promise(r => setTimeout(r, 500));

                    // 自分がホストとして再開
                    this.showNotification('通話', '通話に応答がないため、自分がホストになります', 'info', 2500);
                    // _startGroupMeshCall を呼ぶと自動的にホストとして起動
                    this._startGroupMeshCall(groupId).catch(e => {
                        console.warn('[mesh] ゾンビ通話の回復失敗:', e);
                        this._meshExitUI();
                    });
                    return;
                }

                // 1対1通話の場合は単純に終了
                this.showNotification('エラー', 'ホストへの接続に失敗しました。通話を終了します', 'error');
                this._leaveMeshCall(true).catch(() => { });
                return;
            }

            // Firebaseから最新のhostPeerIdを取得して再試行
            if (this.meshGroupId) {
                try { await this._loadGroups(); } catch (_) { }
                const entry = this.activeGroupCalls.get(this.meshGroupId);
                if (entry?.hostPeerId) {
                    this._meshTargetHostPeerId = entry.hostPeerId;
                    this.meshHostName = entry.hostName;
                    // 新しいhostPeerIdで再試行
                    this._meshTryConnectHost(entry.hostPeerId);
                    return;
                }
            }
            // グループ通話以外、または新hostPeerIdが取れなければ同じIDで再試行
            this._meshTryConnectHost(hostPeerId);
        }, 4000);
    }

    // ====================================================
    // メッシュ通話入室時のUI切替
    // ====================================================
    _meshEnterUI() {
        // 既存videoGrid（2分割）は使わない。meshGridを表示
        if (this.el.waitingState) this.el.waitingState.style.display = 'none';
        if (this.el.videoGrid) this.el.videoGrid.style.display = 'none';
        if (this.el.callControls) this.el.callControls.style.display = '';
        this.showUserListSection(false);

        // meshGridを表示
        const meshGrid = document.getElementById('videoMeshGrid');
        if (meshGrid) {
            meshGrid.style.display = '';
            meshGrid.innerHTML = '';
            meshGrid.dataset.count = '0';
        }

        // 招待ボタンを表示
        this._meshUpdateInviteButtonVisibility();

        // remoteName欄にルーム情報を表示（旧UIだが残置）
        if (this.el.remoteName) {
            if (this.meshGroupName) {
                this.el.remoteName.textContent = `[グループ] ${this.meshGroupName}`;
            } else {
                this.el.remoteName.textContent = this.meshIsHost ? `ホスト: あなた` : `ホスト: ${this.meshHostName}`;
            }
        }

        // マイク/カメラ/画面共有ボタンの状態を反映
        this._meshSyncControlButtonsUI();

        // 初期ステータス
        this._meshUpdateCallStatus();

        // グループ通話バナーが見えていれば更新（自分がそのグループの通話に参加した）
        if (this.meshGroupId) {
            this._updateGroupCallBanner(this.meshGroupId);
        }

        // ヘッダグループバッジ（通話進行中のドット表示）も更新
        this._updateGroupBadge();
    }

    _meshUpdateInviteButtonVisibility() {
        const btn = document.getElementById('meshInviteBtn');
        if (!btn) return;
        // グループ通話中は招待ボタンを隠す（グループメンバーは自分で参加できるため）
        // 1対1通話中のみ招待ボタンを表示
        if (this._meshIsInCall() && !this.meshGroupId) {
            btn.style.display = '';
        } else {
            btn.style.display = 'none';
        }
    }

    // ====================================================
    // 着信通話の処理
    // ====================================================
    _meshHandleIncomingCall(call) {
        const remoteId = call.peer;
        let info = this.meshPeers.get(remoteId);
        if (!info) {
            info = { call: null, conn: null, name: '...', stream: null, micOn: true, camOn: false };
            this.meshPeers.set(remoteId, info);
        }
        info.call = call;
        this._meshEnsureTile(remoteId, false, info.name);

        call.on('stream', stream => {
            info.stream = stream;
            this._meshSetTileStream(remoteId, stream);
        });
        call.on('close', () => this._meshCleanupPeer(remoteId));
        call.on('error', err => console.error('[mesh] call error:', err));
    }

    // ====================================================
    // データ接続
    // ====================================================
    _meshSetupDataConnection(conn) {
        const remoteId = conn.peer;
        let info = this.meshPeers.get(remoteId);
        if (!info) {
            info = { call: null, conn: null, name: '...', stream: null, micOn: true, camOn: false };
            this.meshPeers.set(remoteId, info);
        }
        info.conn = conn;

        conn.on('open', () => {
            // 自己紹介を送信
            try {
                conn.send({
                    type: 'hello',
                    name: this.myName,
                    micOn: this.meshMicOn,
                    camOn: this.meshCamOn,
                    screenSharing: !!this.meshIsScreenSharing
                });
            } catch (_) { }
            // ホストの場合は他参加者リストを送信
            if (this.meshIsHost) {
                const peerList = [...this.meshPeers.keys()].filter(id => id !== remoteId);
                try { conn.send({ type: 'peer-list', peers: peerList }); } catch (_) { }
            }
        });

        conn.on('data', data => this._meshHandleData(remoteId, data));
        conn.on('close', () => this._meshCleanupPeer(remoteId));
    }

    _meshHandleData(remoteId, data) {
        const info = this.meshPeers.get(remoteId);
        if (!info || !data) return;

        switch (data.type) {
            case 'hello':
                info.name = data.name || '匿名';
                info.micOn = data.micOn !== false;
                info.camOn = data.camOn === true;
                info.screenSharing = !!data.screenSharing;
                this._meshEnsureTile(remoteId, false, info.name);
                this._meshSetTileName(remoteId, info.name);
                this._meshSetTileStatus(remoteId, info.micOn, info.camOn);
                // 「参加しました」トーストは表示しない（タイルの追加だけで参加が分かる）
                // 着信モーダルなどが残っていれば閉じる（自分が招待した人が入ってきたケース）
                this.outgoingMeshInvitees.delete(info.name);
                // ホスト接続成功ならホスト接続タイムアウトをクリア
                if (remoteId === this._meshTargetHostPeerId) {
                    clearTimeout(this._meshHostConnectTimeoutId);
                    this._meshHostConnectTimeoutId = null;
                    this._meshHostConnectAttempt = 0;
                }
                // ステータス更新
                this._meshUpdateCallStatus();
                break;
            case 'peer-list':
                // ホストから他参加者を受け取った → それぞれに接続
                (data.peers || []).forEach(pid => {
                    if (pid !== this.meshMyId && !this.meshPeers.has(pid)) {
                        this._meshConnectToPeer(pid);
                    }
                });
                break;
            case 'state':
                info.micOn = data.micOn !== false;
                info.camOn = data.camOn === true;
                info.screenSharing = !!data.screenSharing;
                this._meshSetTileStatus(remoteId, info.micOn, info.camOn);
                break;
            case 'bye':
                this._meshCleanupPeer(remoteId);
                break;
            case 'host-handover':
                // ホストが退出する直前に、新ホスト候補を全員に通知
                // data: { newHostName }
                this._onMeshHostHandover(data, remoteId);
                break;
        }
    }

    // ホスト譲渡通知を受信した
    // - 自分が newHostName なら新ホストに昇格（新Peer立ち上げ＋Firebase更新）
    // - そうでなければ、Firebase の activeCall.hostPeerId 更新を待つ（subscribeで反映される）
    async _onMeshHostHandover(data, fromRemoteId) {
        if (!this._meshIsInCall() || !this.meshGroupId) return;
        const newHostName = data?.newHostName;
        if (!newHostName) return;

        // 旧ホスト名を更新（後でFirebase反映を待たずに表示などに使う）
        this.meshHostName = newHostName;

        if (newHostName === this.myName) {
            // 自分が新ホストとして昇格する
            await this._meshPromoteToHost();
        }
        // 他のメンバーは Firebase の activeCall.hostPeerId の更新を待つ
    }

    // 自分が新ホストに昇格する: 既存のmeshPeerを破棄して新規Peerを立ち上げ、Firebaseに登録、全員に通知
    async _meshPromoteToHost() {
        if (!this.meshGroupId) return;
        this._meshLog('promoting self to host');
        // ホスト切替の表示はしない（ユーザーには気付かれないようにシームレスに）

        // 既存の参加者全員に bye を送信（旧PeerIDのタイル・接続をクリーンアップしてもらう）
        try { this._meshBroadcastBye(); } catch (_) { }

        // 既存のPeerを破棄
        if (this.meshPeer) {
            try { this.meshPeer.destroy(); } catch (_) { }
            this.meshPeer = null;
        }
        // 既存のmeshPeersをクリア（call/connはdestroyで切れる）
        const oldMyId = this.meshMyId;
        this.meshPeers.forEach(info => {
            if (info.call) { try { info.call.close(); } catch (_) { } }
            if (info.conn) { try { info.conn.close(); } catch (_) { } }
        });
        this.meshPeers.clear();

        // 自分のタイルも作り直し（PeerIDが変わるため）
        if (oldMyId) this._meshRemoveTile(oldMyId);

        // 少し待つ（PeerJSサーバー上の旧PeerIDが解放される時間 + bye受信処理時間）
        await new Promise(r => setTimeout(r, 600));

        // 新規にホストPeerを起動（グループ通話なのでランダムサフィックス付き → unavailable-id問題なし）
        this.meshIsHost = true;
        this.meshHostName = this.myName;
        try {
            await this._meshInitPeer(this.meshHostName, true, {
                isGroupCall: true,
                groupId: this.meshGroupId
            });
        } catch (e) {
            console.warn('[mesh] ホスト昇格失敗:', e);
            this.showNotification('エラー', 'ホスト交代に失敗しました。通話を終了します', 'error');
            this._leaveMeshCall(true).catch(() => { });
            return;
        }

        // 自分のタイルを再作成（新PeerID で）
        this._meshEnsureTile(this.meshMyId, true, this.myName);
        this._meshSetTileStream(this.meshMyId, this.localStream);
        this._meshSetTileStatus(this.meshMyId, this.meshMicOn, this.meshCamOn);

        // Firebase の activeCall を新ホスト情報で更新（他メンバーは購読で気付いて自分に繋ぎ直す）
        try {
            const res = await FbAPI.updateGroupCallHost(this.token, this.meshGroupId, this.myName, this.meshMyId);
            if (!res.ok) {
                console.warn('[mesh] updateGroupCallHost failed:', res.error);
            }
            // 新ホストも onDisconnect 予約を設定
            await FbAPI.setupActiveCallOnDisconnect(this.meshGroupId);
        } catch (e) {
            console.warn('[mesh] updateGroupCallHost error:', e);
        }

        // 自分の activeGroupCalls エントリも更新
        this.activeGroupCalls.set(this.meshGroupId, {
            hostName: this.myName,
            hostPeerId: this.meshMyId,
            groupName: this.meshGroupName,
            startedAt: Date.now()
        });

        // 「ホストを引き継ぎました」トーストは表示しない（ユーザー要望）
        this._meshUpdateCallStatus();
        if (this.meshGroupId) this._updateGroupCallBanner(this.meshGroupId);
    }

    _meshOriginalHandleDataPlaceholder() {
        // (no-op)
    }

    // ====================================================
    // 他peerへ接続
    // ====================================================
    _meshConnectToPeer(remotePeerId) {
        if (!remotePeerId || remotePeerId === this.meshMyId) return;
        if (this.meshPeers.has(remotePeerId) && this.meshPeers.get(remotePeerId).conn) return;

        const conn = this.meshPeer.connect(remotePeerId, { reliable: true });
        this._meshSetupDataConnection(conn);

        const call = this.meshPeer.call(remotePeerId, this.localStream || undefined);
        if (call) {
            let info = this.meshPeers.get(remotePeerId);
            if (!info) {
                info = { call: null, conn: null, name: '...', stream: null, micOn: true, camOn: false };
                this.meshPeers.set(remotePeerId, info);
            }
            info.call = call;
            this._meshEnsureTile(remotePeerId, false, info.name);

            call.on('stream', stream => {
                info.stream = stream;
                this._meshSetTileStream(remotePeerId, stream);
            });
            call.on('close', () => this._meshCleanupPeer(remotePeerId));
            call.on('error', err => console.error('[mesh] call error:', err));
        }
    }

    _meshCleanupPeer(peerId) {
        const info = this.meshPeers.get(peerId);
        if (info) {
            if (info.call) { try { info.call.close(); } catch (_) { } }
            if (info.conn) { try { info.conn.close(); } catch (_) { } }
            // 「退出しました」トーストは表示しない（タイルの消失だけで退出が分かる）
            this.meshPeers.delete(peerId);
        }
        this._meshRemoveTile(peerId);
        // ステータス更新
        this._meshUpdateCallStatus();
    }

    _meshBroadcastState() {
        const msg = {
            type: 'state',
            micOn: this.meshMicOn,
            camOn: this.meshCamOn,
            screenSharing: !!this.meshIsScreenSharing
        };
        this.meshPeers.forEach(info => {
            if (info.conn && info.conn.open) {
                try { info.conn.send(msg); } catch (_) { }
            }
        });
    }

    _meshBroadcastBye() {
        if (!this.meshPeer) return;
        this.meshPeers.forEach(info => {
            if (info.conn && info.conn.open) {
                try { info.conn.send({ type: 'bye' }); } catch (_) { }
            }
        });
    }

    // 通話人数に応じてステータスを更新する
    _meshUpdateCallStatus() {
        if (!this._meshIsInCall()) return;
        // 接続済みの参加者数（hello を受信して名前が確定した人）
        let connectedCount = 0;
        this.meshPeers.forEach(info => {
            if (info.name && info.name !== '...') connectedCount++;
        });
        const total = connectedCount + 1; // 自分を含めた人数
        if (total >= 2) {
            // ラベル文言: グループ通話なら "通話中 - グループ:○○ (N人)"
            if (this.meshGroupName) {
                this.updateStatus(`通話中 - ${this.meshGroupName} (${total}人)`);
            } else {
                this.updateStatus(`通話中 (${total}人)`);
            }
        } else {
            // 1人だけ（=待機中）
            if (this.meshIsHost) {
                if (this.meshGroupId) {
                    this.updateStatus('待機中 - メンバーの参加を待っています');
                } else {
                    this.updateStatus('待機中 - 招待してください');
                }
            } else {
                this.updateStatus('ホストに接続中...');
            }
        }
    }

    // ====================================================
    // タイル管理
    // ====================================================
    _meshEnsureTile(peerId, isSelf, name) {
        const grid = document.getElementById('videoMeshGrid');
        if (!grid) return null;
        let tile = grid.querySelector(`[data-mtile="${CSS.escape(peerId)}"]`);
        if (tile) return tile;

        tile = document.createElement('div');
        tile.className = 'mesh-tile' + (isSelf ? ' self' : '');
        tile.dataset.mtile = peerId;
        const initial = (name || '?').charAt(0).toUpperCase();
        tile.innerHTML = `
            <video autoplay playsinline ${isSelf ? 'muted' : ''}></video>
            <div class="mesh-no-video">
                <div class="mesh-no-video-circle"><span>${this._escapeHtml(initial)}</span></div>
            </div>
            <div class="mesh-tile-label">
                <span class="mesh-tile-name">${this._escapeHtml(name || '...')}</span>${isSelf ? ' <span class="mesh-tile-you">(あなた)</span>' : ''}
            </div>
            <div class="mesh-tile-status"></div>
            <button class="mesh-tile-pin-btn" title="ピン留め" tabindex="-1"><i class="fas fa-thumbtack"></i></button>
        `;
        // アバター画像を反映
        try {
            const av = this.avatarCache?.[name];
            if (av) {
                const circle = tile.querySelector('.mesh-no-video-circle');
                if (circle) {
                    circle.innerHTML = `<img src="${av}" alt="">`;
                }
            }
        } catch (_) { }
        // ピン留め: 右クリック / ピンボタンクリック / ダブルクリック
        tile.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            this._meshShowPinMenu(peerId, e.clientX, e.clientY);
        });
        tile.addEventListener('dblclick', () => {
            this._meshTogglePin(peerId);
        });
        const pinBtn = tile.querySelector('.mesh-tile-pin-btn');
        if (pinBtn) {
            pinBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this._meshTogglePin(peerId);
            });
        }

        grid.appendChild(tile);
        this._meshUpdateGridCount();
        this._meshApplyPinState();
        return tile;
    }

    // タイル数だけでなく、ピン留め状態も再計算してグリッドに反映
    _meshApplyPinState() {
        const grid = document.getElementById('videoMeshGrid');
        if (!grid) return;
        const pinnedId = this._meshPinnedPeerId;
        // pinned が存在しない場合は解除
        if (pinnedId) {
            const existingPinned = grid.querySelector(`[data-mtile="${CSS.escape(pinnedId)}"]`);
            if (!existingPinned) {
                this._meshPinnedPeerId = null;
            }
        }
        // 全タイルからpinnedクラスを外す
        grid.querySelectorAll('.mesh-tile').forEach(t => t.classList.remove('pinned'));
        if (this._meshPinnedPeerId) {
            const t = grid.querySelector(`[data-mtile="${CSS.escape(this._meshPinnedPeerId)}"]`);
            if (t) {
                t.classList.add('pinned');
                grid.dataset.pinned = 'true';
                // ピン留めタイルを先頭に移動
                grid.insertBefore(t, grid.firstChild);
                return;
            }
        }
        delete grid.dataset.pinned;
    }

    // ピン留めをトグル
    _meshTogglePin(peerId) {
        if (this._meshPinnedPeerId === peerId) {
            this._meshPinnedPeerId = null;
        } else {
            this._meshPinnedPeerId = peerId;
        }
        this._meshApplyPinState();
        this._meshHidePinMenu();
    }

    // 右クリックメニュー表示
    _meshShowPinMenu(peerId, x, y) {
        let menu = document.getElementById('meshPinMenu');
        if (!menu) {
            menu = document.createElement('div');
            menu.id = 'meshPinMenu';
            menu.className = 'mesh-pin-menu';
            document.body.appendChild(menu);
            // 外をクリックで閉じる
            document.addEventListener('click', () => this._meshHidePinMenu());
            document.addEventListener('contextmenu', (e) => {
                if (!menu.contains(e.target)) this._meshHidePinMenu();
            });
        }
        const isPinned = this._meshPinnedPeerId === peerId;
        menu.innerHTML = `
            <button class="mesh-pin-menu-item" data-action="${isPinned ? 'unpin' : 'pin'}">
                <i class="fas fa-thumbtack"></i> ${isPinned ? 'ピン留めを解除' : 'ピン留めして拡大表示'}
            </button>
        `;
        menu.style.display = 'block';
        // 画面端で見切れない位置調整
        const w = 200, h = 50;
        const vw = window.innerWidth, vh = window.innerHeight;
        const left = Math.min(x, vw - w - 8);
        const top = Math.min(y, vh - h - 8);
        menu.style.left = left + 'px';
        menu.style.top = top + 'px';
        const btn = menu.querySelector('button');
        if (btn) {
            btn.onclick = (e) => {
                e.stopPropagation();
                this._meshTogglePin(peerId);
            };
        }
    }

    _meshHidePinMenu() {
        const menu = document.getElementById('meshPinMenu');
        if (menu) menu.style.display = 'none';
    }

    _meshRemoveTile(peerId) {
        const grid = document.getElementById('videoMeshGrid');
        if (!grid) return;
        const tile = grid.querySelector(`[data-mtile="${CSS.escape(peerId)}"]`);
        if (tile) tile.remove();
        // 削除されたタイルがピン留め対象だったら解除
        if (this._meshPinnedPeerId === peerId) {
            this._meshPinnedPeerId = null;
        }
        this._meshUpdateGridCount();
        this._meshApplyPinState();
    }

    _meshUpdateGridCount() {
        const grid = document.getElementById('videoMeshGrid');
        if (!grid) return;
        const n = grid.children.length;
        grid.dataset.count = String(n);
    }

    _meshSetTileStream(peerId, stream) {
        const grid = document.getElementById('videoMeshGrid');
        if (!grid) return;
        const tile = grid.querySelector(`[data-mtile="${CSS.escape(peerId)}"]`);
        if (!tile) return;
        const video = tile.querySelector('video');
        if (video && video.srcObject !== stream) {
            video.srcObject = stream;
        }
        this._meshRefreshTileVideoState(peerId);
    }

    _meshSetTileName(peerId, name) {
        const grid = document.getElementById('videoMeshGrid');
        if (!grid) return;
        const tile = grid.querySelector(`[data-mtile="${CSS.escape(peerId)}"]`);
        if (!tile) return;
        const nameEl = tile.querySelector('.mesh-tile-name');
        if (nameEl) nameEl.textContent = name || '...';
        // アバター
        try {
            const av = this.avatarCache?.[name];
            const circle = tile.querySelector('.mesh-no-video-circle');
            if (circle) {
                if (av) circle.innerHTML = `<img src="${av}" alt="">`;
                else circle.innerHTML = `<span>${this._escapeHtml((name || '?').charAt(0).toUpperCase())}</span>`;
            }
        } catch (_) { }
    }

    _meshSetTileStatus(peerId, micOn, camOn) {
        const grid = document.getElementById('videoMeshGrid');
        if (!grid) return;
        const tile = grid.querySelector(`[data-mtile="${CSS.escape(peerId)}"]`);
        if (!tile) return;
        const statusEl = tile.querySelector('.mesh-tile-status');
        if (statusEl) {
            statusEl.innerHTML = '';
            if (!micOn) {
                statusEl.innerHTML += `<div class="mesh-status-icon muted" title="ミュート"><i class="fas fa-microphone-slash"></i></div>`;
            }
        }
        const overlay = tile.querySelector('.mesh-no-video');
        const video = tile.querySelector('video');
        if (camOn) {
            if (overlay) overlay.style.display = 'none';
            if (video) video.style.opacity = '1';
        } else {
            if (overlay) overlay.style.display = 'flex';
            if (video) video.style.opacity = '0';
        }
    }

    _meshRefreshTileVideoState(peerId) {
        const grid = document.getElementById('videoMeshGrid');
        if (!grid) return;
        const tile = grid.querySelector(`[data-mtile="${CSS.escape(peerId)}"]`);
        if (!tile) return;
        const video = tile.querySelector('video');
        const stream = video?.srcObject;
        if (!stream) return;
        const v = stream.getVideoTracks()[0];
        const a = stream.getAudioTracks()[0];
        const camOn = v && v.enabled && !v.muted;
        const micOn = a && a.enabled && !a.muted;
        // 相手情報を優先（hello/state で受け取った camOn/micOn を使う）
        const info = this.meshPeers.get(peerId);
        const finalMic = info ? info.micOn : micOn;
        const finalCam = info ? info.camOn : camOn;
        this._meshSetTileStatus(peerId, finalMic, finalCam);
    }

    // ====================================================
    // 退出
    // ====================================================
    async _leaveMeshCall(silent = false) {
        if (!this._meshIsInCall()) return;
        if (!silent) {
            const ok = confirm('通話から退出しますか？');
            if (!ok) return;
        }

        // グループ通話のホストが退出する場合の処理
        const wasGroupCall = !!this.meshGroupId;
        const wasHost = this.meshIsHost;
        const wasGroupId = this.meshGroupId;

        // ホスト譲渡の判定: グループ通話で自分がホストで残メンバーがいる場合は譲渡
        let didHandover = false;
        if (wasGroupCall && wasHost && wasGroupId && this.meshPeers.size > 0) {
            // 残メンバーから新ホスト候補を選定
            // 選定基準: 名前が確定済みのメンバーの中で、名前の辞書順で最初の人
            const candidates = [];
            this.meshPeers.forEach((info, pid) => {
                if (info.name && info.name !== '...' && info.conn && info.conn.open) {
                    candidates.push({ pid, name: info.name });
                }
            });
            if (candidates.length > 0) {
                candidates.sort((a, b) => a.name.localeCompare(b.name, 'ja'));
                const newHost = candidates[0];
                // 全員に host-handover を送信
                this.meshPeers.forEach(info => {
                    if (info.conn && info.conn.open) {
                        try { info.conn.send({ type: 'host-handover', newHostName: newHost.name }); } catch (_) { }
                    }
                });
                // 自分の onDisconnect 予約をキャンセル（自分が退出しても activeCall を消さない）
                // 新ホストB が自分の onDisconnect を新たに予約済み
                try { await FbAPI.cancelActiveCallOnDisconnect(wasGroupId); } catch (_) { }

                didHandover = true;
                this._meshLog('host handover to', newHost.name);
                // 譲渡シグナルがネットワークを伝わるまで少し待つ（800ms）
                await new Promise(r => setTimeout(r, 800));
            }
        }

        // 通話終了通知（譲渡しなかった or 譲渡対象がいない場合のみ）
        if (wasGroupCall && wasHost && wasGroupId && !didHandover) {
            const group = this.myGroups.find(g => g.id === wasGroupId);
            if (group) {
                const otherMembers = (group.members || []).filter(m => m !== this.myName);
                const endPayload = encodeURIComponent(JSON.stringify({ groupId: wasGroupId }));
                for (const member of otherMembers) {
                    try {
                        await FbAPI.sendSignal(this.token, member, 'group_call_end', endPayload);
                    } catch (_) { }
                }
            }
            // Firebase上の進行中通話を削除（ログイン中でないメンバーに対しても反映）
            try { await FbAPI.clearGroupActiveCall(this.token, wasGroupId); } catch (_) { }
            // 自分のactiveGroupCallsからも削除
            this.activeGroupCalls.delete(wasGroupId);
        }

        // 全員にbye送信
        try { this._meshBroadcastBye(); } catch (_) { }
        // 招待中の相手にもキャンセル通知
        if (this.outgoingMeshInvitees && this.outgoingMeshInvitees.size > 0) {
            for (const name of Array.from(this.outgoingMeshInvitees)) {
                try {
                    await FbAPI.sendSignal(this.token, name, 'mesh_invite_cancel',
                        encodeURIComponent(JSON.stringify({ roomId: this.meshRoomId })));
                } catch (_) { }
            }
            this.outgoingMeshInvitees.clear();
        }
        // peer破棄
        try {
            this.meshPeers.forEach(info => {
                if (info.call) { try { info.call.close(); } catch (_) { } }
                if (info.conn) { try { info.conn.close(); } catch (_) { } }
            });
        } catch (_) { }
        this.meshPeers.clear();
        if (this.meshPeer) {
            try { this.meshPeer.destroy(); } catch (_) { }
        }
        this.meshPeer = null;
        this.meshMyId = null;

        // 画面共有解除
        if (this.meshIsScreenSharing) {
            try { await this._meshStopScreenShare(); } catch (_) { }
        }

        this._meshClearState();
        this._meshExitUI();

        // 退出後、グループチャットを開いていたらバナー更新
        if (wasGroupCall && wasGroupId &&
            this.currentGroupId === wasGroupId &&
            this.el.groupModal?.classList.contains('visible') &&
            this.el.groupChatArea?.style.display !== 'none') {
            this._updateGroupCallBanner(wasGroupId);
        }
        this._refreshGroupListCallIndicator();
        this._updateGroupBadge();
    }

    _meshClearState() {
        this.meshRoomId = null;
        this.meshHostName = null;
        this.meshIsHost = false;
        this.meshGroupId = null;
        this.meshGroupName = null;
        this.meshIsScreenSharing = false;
        this.meshSavedCameraTrack = null;
        this._meshTargetHostPeerId = null;
        if (this._meshHostConnectTimeoutId) {
            clearTimeout(this._meshHostConnectTimeoutId);
            this._meshHostConnectTimeoutId = null;
        }
        this._meshHostConnectAttempt = 0;
        if (this.outgoingMeshInvitees) this.outgoingMeshInvitees.clear();
        // メディア状態をリセット（カメラOFF/マイクON）
        this.meshMicOn = true;
        this.meshCamOn = false;
        if (this.localStream) {
            try {
                this.localStream.getAudioTracks().forEach(t => t.enabled = true);
                this.localStream.getVideoTracks().forEach(t => t.enabled = false);
            } catch (_) { }
        }
    }

    _meshExitUI() {
        const meshGrid = document.getElementById('videoMeshGrid');
        if (meshGrid) {
            meshGrid.innerHTML = '';
            meshGrid.style.display = 'none';
            delete meshGrid.dataset.pinned;
        }
        if (this.el.videoGrid) this.el.videoGrid.style.display = 'none';
        if (this.el.waitingState) this.el.waitingState.style.display = '';
        if (this.el.callControls) this.el.callControls.style.display = 'none';
        this.showUserListSection(true);
        this._meshUpdateInviteButtonVisibility();
        this.callTargetName = null;
        this._meshPinnedPeerId = null;
        this._meshHidePinMenu();
        this.updateStatus('オンライン');
        // ボタン状態を初期に戻す
        this._meshSyncControlButtonsUI();
        // 通話終了後はグループバッジを更新（通話進行中インジケータの再評価）
        this._updateGroupBadge();
    }

    _meshSyncControlButtonsUI() {
        // 既存のtoggleMic/toggleVideoボタンを流用する
        if (this.el.toggleMicButton) {
            this.el.toggleMicButton.classList.toggle('active', !this.meshMicOn);
            const icon = this.el.toggleMicButton.querySelector('i');
            if (icon) icon.className = this.meshMicOn ? 'fas fa-microphone' : 'fas fa-microphone-slash';
        }
        if (this.el.toggleVideoButton) {
            this.el.toggleVideoButton.classList.toggle('active', !this.meshCamOn);
            const icon = this.el.toggleVideoButton.querySelector('i');
            if (icon) icon.className = this.meshCamOn ? 'fas fa-video' : 'fas fa-video-slash';
        }
        if (this.el.screenShareButton) {
            this.el.screenShareButton.classList.toggle('sharing', !!this.meshIsScreenSharing);
            const icon = this.el.screenShareButton.querySelector('i');
            if (icon) icon.className = this.meshIsScreenSharing ? 'fas fa-stop' : 'fas fa-desktop';
            this.el.screenShareButton.title = this.meshIsScreenSharing ? '画面共有を停止' : '画面共有';
        }
    }

    // ====================================================
    // マイク/カメラ/画面共有（メッシュ版）
    // ====================================================
    _meshToggleMic() {
        this.meshMicOn = !this.meshMicOn;
        if (this.localStream) {
            this.localStream.getAudioTracks().forEach(t => t.enabled = this.meshMicOn);
        }
        this._meshSetTileStatus(this.meshMyId, this.meshMicOn, this.meshCamOn);
        this._meshSyncControlButtonsUI();
        this._meshBroadcastState();
    }

    _meshToggleCam() {
        // 画面共有中はカメラトグル不可
        if (this.meshIsScreenSharing) {
            this.showNotification('通知', '画面共有中はカメラを切り替えできません', 'warning');
            return;
        }
        this.meshCamOn = !this.meshCamOn;
        if (this.localStream) {
            this.localStream.getVideoTracks().forEach(t => t.enabled = this.meshCamOn);
        }
        this._meshSetTileStatus(this.meshMyId, this.meshMicOn, this.meshCamOn);
        this._meshSyncControlButtonsUI();
        this._meshBroadcastState();
    }

    // 画面共有: 全meshPeer に対して replaceTrack
    async _meshToggleScreenShare() {
        if (this.meshIsScreenSharing) {
            await this._meshStopScreenShare();
        } else {
            await this._meshStartScreenShare();
        }
    }

    async _meshStartScreenShare() {
        try {
            const dispStream = await navigator.mediaDevices.getDisplayMedia({
                video: { cursor: 'always' },
                audio: false
            });
            const screenTrack = dispStream.getVideoTracks()[0];
            if (!screenTrack) return;

            // 既存のカメラトラックを退避
            const oldVideoTrack = this.localStream?.getVideoTracks()[0] || null;
            this.meshSavedCameraTrack = oldVideoTrack;

            // localStreamのビデオトラックを差し替え
            if (this.localStream) {
                if (oldVideoTrack) this.localStream.removeTrack(oldVideoTrack);
                this.localStream.addTrack(screenTrack);
            } else {
                this.localStream = dispStream;
            }

            // 全peerに対して replaceTrack
            this.meshPeers.forEach(info => {
                if (info.call && info.call.peerConnection) {
                    const senders = info.call.peerConnection.getSenders();
                    const vSender = senders.find(s => s.track && s.track.kind === 'video');
                    if (vSender) {
                        try { vSender.replaceTrack(screenTrack); } catch (_) { }
                    } else {
                        // 新規追加
                        try { info.call.peerConnection.addTrack(screenTrack, this.localStream); } catch (_) { }
                    }
                }
            });

            // 自分のタイル映像を差し替え
            this._meshSetTileStream(this.meshMyId, this.localStream);

            this.meshIsScreenSharing = true;
            this.meshCamOn = true; // 画面共有中はビデオが流れているのでcamOn扱い
            screenTrack.onended = () => { this._meshStopScreenShare().catch(() => { }); };

            this._meshSyncControlButtonsUI();
            this._meshSetTileStatus(this.meshMyId, this.meshMicOn, this.meshCamOn);
            this._meshBroadcastState();
        } catch (e) {
            console.warn('[mesh] screenshare cancelled or failed:', e);
        }
    }

    async _meshStopScreenShare() {
        if (!this.meshIsScreenSharing) return;
        // 退避していたカメラトラックがあるなら戻す。なければ新規取得。
        let cameraTrack = this.meshSavedCameraTrack;
        if (!cameraTrack || cameraTrack.readyState === 'ended') {
            try {
                const camStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
                cameraTrack = camStream.getVideoTracks()[0];
            } catch (_) {
                cameraTrack = null;
            }
        }

        // 現在のlocalStreamの画面共有トラックを除去
        if (this.localStream) {
            const cur = this.localStream.getVideoTracks()[0];
            if (cur) {
                try { cur.stop(); } catch (_) { }
                this.localStream.removeTrack(cur);
            }
            if (cameraTrack) {
                cameraTrack.enabled = false; // カメラOFFに戻す
                this.localStream.addTrack(cameraTrack);
            }
        }

        // 全peerに対して replaceTrack
        this.meshPeers.forEach(info => {
            if (info.call && info.call.peerConnection) {
                const senders = info.call.peerConnection.getSenders();
                const vSender = senders.find(s => s.track && s.track.kind === 'video');
                if (vSender) {
                    try { vSender.replaceTrack(cameraTrack || null); } catch (_) { }
                }
            }
        });

        this._meshSetTileStream(this.meshMyId, this.localStream);
        this.meshIsScreenSharing = false;
        this.meshSavedCameraTrack = null;
        this.meshCamOn = false; // カメラOFFに戻す（要件）
        this._meshSyncControlButtonsUI();
        this._meshSetTileStatus(this.meshMyId, this.meshMicOn, this.meshCamOn);
        this._meshBroadcastState();
    }

    // ====================================================
    // 招待・着信
    // ====================================================

    // [入口] 1対1通話の開始（旧 startOutgoingCall の置き換え）
    async _startOneToOneMeshCall(targetName) {
        if (this._meshIsInCall()) {
            // 既に通話中 → 招待
            return this._inviteToMeshCall(targetName);
        }
        if (!this.friendNames.has(targetName)) {
            this.showNotification('通知', 'フレンドのみ通話できます', 'warning');
            return;
        }
        if (this.blockedUsers.has(targetName)) {
            this.showNotification('通知', 'ブロック中のユーザーには発信できません', 'warning');
            return;
        }

        // 自分がホストとして通話を開始
        const ok = await this._startMeshCall({ hostName: this.myName, isHost: true });
        if (!ok) return;

        // 相手に招待を送信し、callingModal表示
        this.callTargetName = targetName;
        this.el.callingTargetName.textContent = targetName;
        this.el.callingModal.classList.add('visible');
        this.outgoingMeshInvitees.add(targetName);

        try {
            const payload = encodeURIComponent(JSON.stringify({
                roomId: this.meshRoomId,
                hostName: this.myName,
                inviterName: this.myName,
                isGroupCall: false
            }));
            const res = await FbAPI.sendSignal(this.token, targetName, 'mesh_invite', payload);
            if (!res.ok) {
                this.el.callingModal.classList.remove('visible');
                this.outgoingMeshInvitees.delete(targetName);
                this.showNotification('エラー', '通話申請の送信に失敗しました: ' + (res.error || ''), 'error');
                await this._leaveMeshCall(true);
                return;
            }
        } catch (e) {
            this.el.callingModal.classList.remove('visible');
            this.outgoingMeshInvitees.delete(targetName);
            this.showNotification('エラー', '通話申請の送信に失敗しました', 'error');
            await this._leaveMeshCall(true);
            return;
        }

        // タイムアウト（30秒）
        clearTimeout(this._meshCallTimeout);
        this._meshCallTimeout = setTimeout(async () => {
            if (this.outgoingMeshInvitees.has(targetName)) {
                this.outgoingMeshInvitees.delete(targetName);
                if (this.el.callingModal.classList.contains('visible')) {
                    this.el.callingModal.classList.remove('visible');
                    this.showNotification('通知', '通話申請がタイムアウトしました', 'warning');
                }
                // 1対1呼び出しでタイムアウトなら通話自体を終了
                if (this.meshPeers.size === 0) {
                    await this._leaveMeshCall(true);
                }
            }
        }, 30000);
    }

    // [入口] グループ通話の開始
    async _startGroupMeshCall(groupId) {
        // 最新のメンバー情報を取得（招待直後でキャッシュが古い場合に対応）
        try { await this._loadGroups(); } catch (_) { }

        const group = this.myGroups.find(g => g.id === groupId);
        if (!group) {
            this.showNotification('エラー', 'グループが見つかりません', 'error');
            return;
        }
        if (this._meshIsInCall()) {
            this.showNotification('通知', '既に通話中です', 'warning');
            return;
        }

        // 既に他のホストの通話が進行中なら参加に誘導
        if (this.activeGroupCalls.has(groupId)) {
            const entry = this.activeGroupCalls.get(groupId);
            if (entry.hostName !== this.myName) {
                // 別ホストの通話があるなら参加する
                return this._joinActiveGroupCall(groupId);
            }
        }

        // Firebaseのグループに進行中通話を登録（他のメンバーがログイン中でなくても、後から見える）
        try {
            const res = await FbAPI.setGroupActiveCall(this.token, groupId, this.myName);
            if (!res.ok) {
                // 既に別ホストの通話が立っていた場合はそちらに参加する
                if (res.existing && res.existing.hostName && res.existing.hostName !== this.myName) {
                    this.activeGroupCalls.set(groupId, {
                        hostName: res.existing.hostName,
                        groupName: group.name,
                        startedAt: res.existing.startedAt || Date.now()
                    });
                    this.showNotification('通知', `既に ${res.existing.hostName} さんが通話を開始しています。参加します。`, 'info', 2200);
                    return this._joinActiveGroupCall(groupId);
                }
                this.showNotification('エラー', '通話の登録に失敗しました: ' + (res.error || ''), 'error');
                return;
            }
        } catch (e) {
            this.showNotification('エラー', '通話の登録に失敗しました', 'error');
            return;
        }

        // 先に activeGroupCalls に登録（_startMeshCall → _meshEnterUI → _updateGroupCallBanner が参照するため）
        this.activeGroupCalls.set(group.id, {
            hostName: this.myName,
            groupName: group.name,
            startedAt: Date.now()
        });

        // 自分がホストとして通話を開始
        const ok = await this._startMeshCall({
            hostName: this.myName,
            isHost: true,
            groupContext: { groupId: group.id, groupName: group.name }
        });
        if (!ok) {
            // 失敗したら登録も取り消す
            this.activeGroupCalls.delete(group.id);
            try { await FbAPI.clearGroupActiveCall(this.token, group.id); } catch (_) { }
            this._updateGroupBadge();
            this._refreshGroupListCallIndicator();
            return;
        }

        // グループの他メンバー全員に「通話開始通知」を送信（オンライン中のメンバーへの即時通知用、補助）
        const members = (group.members || []).filter(m => m !== this.myName);
        if (members.length === 0) {
            this.showNotification('通知', 'グループに他のメンバーがいません。あなた1人で待機中です', 'warning');
            return;
        }
        const payload = encodeURIComponent(JSON.stringify({
            roomId: this.meshRoomId,
            hostName: this.myName,
            groupId: group.id,
            groupName: group.name
        }));
        for (const member of members) {
            try {
                await FbAPI.sendSignal(this.token, member, 'group_call_notify', payload);
            } catch (e) {
                console.warn('[mesh] グループ通話通知失敗:', member, e);
            }
        }
    }

    // [シグナル受信] グループ通話が始まった通知
    async _onGroupCallNotified(signal) {
        let payload;
        try { payload = JSON.parse(decodeURIComponent(signal.signal_data)); } catch (_) { return; }
        if (!payload || !payload.groupId || !payload.hostName) return;

        // 自分がそのグループのメンバーであることを確認（招待保護）
        let group = this.myGroups.find(g => g.id === payload.groupId);
        // キャッシュにグループが無い、またはメンバー情報が古い場合は再ロード
        if (!group || !(group.members || []).includes(this.myName)) {
            try { await this._loadGroups(); } catch (_) { }
            group = this.myGroups.find(g => g.id === payload.groupId);
        }
        if (!group) return;
        if (!(group.members || []).includes(this.myName)) return;
        if (this.blockedUsers.has(signal.from)) return;
        // 自分自身がホストである通話の通知は無視
        if (payload.hostName === this.myName) return;

        // 進行中リストに登録
        this.activeGroupCalls.set(payload.groupId, {
            hostName: payload.hostName,
            groupName: payload.groupName || group.name,
            startedAt: Date.now()
        });

        // 該当グループチャットを開いていたらバナーを即時更新
        if (this.currentGroupId === payload.groupId &&
            this.el.groupModal?.classList.contains('visible') &&
            this.el.groupChatArea?.style.display !== 'none') {
            this._updateGroupCallBanner(payload.groupId);
        }
        // グループ一覧表示中なら一覧を再描画して通話中インジケータを反映
        if (this.el.groupModal?.classList.contains('visible') &&
            this.el.groupListArea?.style.display !== 'none') {
            this._renderGroupList();
        } else {
            this._refreshGroupListCallIndicator();
        }
        // ヘッダのグループアイコンに「進行中通話あり」を示すドット表示を更新
        this._updateGroupBadge();
    }

    // [シグナル受信] グループ通話が終わった通知（ホストが退出するときに送る）
    _onGroupCallEnded(signal) {
        let payload;
        try { payload = JSON.parse(decodeURIComponent(signal.signal_data)); } catch (_) { return; }
        if (!payload || !payload.groupId) return;
        const entry = this.activeGroupCalls.get(payload.groupId);
        if (!entry) return;
        // ホスト本人からの通知のみ受理
        if (entry.hostName !== signal.from) return;
        this.activeGroupCalls.delete(payload.groupId);
        if (this.currentGroupId === payload.groupId &&
            this.el.groupModal?.classList.contains('visible') &&
            this.el.groupChatArea?.style.display !== 'none') {
            this._updateGroupCallBanner(payload.groupId);
        }
        if (this.el.groupModal?.classList.contains('visible') &&
            this.el.groupListArea?.style.display !== 'none') {
            this._renderGroupList();
        } else {
            this._refreshGroupListCallIndicator();
        }
        this._updateGroupBadge();
    }

    // グループ通話の参加ボタンが押されたときの処理
    async _joinActiveGroupCall(groupId) {
        if (this._meshIsInCall()) {
            if (this.meshGroupId === groupId) {
                this.showNotification('通知', '既にこの通話に参加中です', 'info');
                return;
            }
            this.showNotification('通知', '既に別の通話中です。先に終了してください', 'warning');
            return;
        }
        // 最新の hostPeerId を取得するために Firebase を再ロード
        // （ホスト交代直後はキャッシュが古い可能性があるため）
        try { await this._loadGroups(); } catch (_) { }

        const entry = this.activeGroupCalls.get(groupId);
        if (!entry) {
            this.showNotification('通知', 'この通話は既に終了しています', 'warning');
            this._updateGroupCallBanner(groupId);
            return;
        }
        const group = this.myGroups.find(g => g.id === groupId);
        if (!group) return;
        const hostPeerId = entry.hostPeerId;
        if (!hostPeerId) {
            this.showNotification('エラー', 'ホストPeerIDが取得できません。通話に参加できませんでした', 'error');
            return;
        }
        // ゲストとして参加
        await this._startMeshCall({
            hostName: entry.hostName,
            isHost: false,
            groupContext: {
                groupId: groupId,
                groupName: entry.groupName || group.name,
                hostPeerId: hostPeerId
            }
        });
    }

    // グループチャット内に「通話中バナー」を表示・非表示する
    _updateGroupCallBanner(groupId) {
        const bannerHost = document.getElementById('groupCallBanner');
        // ヘッダの通話ボタンの見た目も同時に切替
        const groupCallBtn = document.getElementById('groupCallBtn');
        const entry = this.activeGroupCalls.get(groupId);
        const alreadyIn = this._meshIsInCall() && this.meshGroupId === groupId;

        // ヘッダボタンの見た目: 進行中 = 「参加」アイコン、無ければ「開始」アイコン
        // 自分が参加中なら無効化（見た目はそのまま）
        if (groupCallBtn) {
            if (alreadyIn) {
                groupCallBtn.disabled = true;
                groupCallBtn.title = '通話に参加中';
                groupCallBtn.innerHTML = '<i class="fas fa-phone-volume"></i>';
            } else if (entry) {
                groupCallBtn.disabled = false;
                groupCallBtn.title = '進行中の通話に参加';
                groupCallBtn.innerHTML = '<i class="fas fa-phone-volume"></i>';
                groupCallBtn.classList.add('joining');
            } else {
                groupCallBtn.disabled = false;
                groupCallBtn.title = 'グループ通話を開始';
                groupCallBtn.innerHTML = '<i class="fas fa-phone"></i>';
                groupCallBtn.classList.remove('joining');
            }
        }

        if (!bannerHost) return;
        if (!entry) {
            bannerHost.style.display = 'none';
            bannerHost.innerHTML = '';
            return;
        }
        bannerHost.style.display = '';
        if (alreadyIn) {
            bannerHost.innerHTML = `
                <div class="group-call-banner-inner active">
                    <i class="fas fa-phone-volume"></i>
                    <span class="group-call-banner-text">この通話に参加中です</span>
                </div>
            `;
        } else {
            bannerHost.innerHTML = `
                <div class="group-call-banner-inner">
                    <i class="fas fa-phone-volume"></i>
                    <span class="group-call-banner-text"><strong>${this._escapeHtml(entry.hostName)}</strong> さんが通話を開始しました</span>
                    <button id="groupCallJoinBtn" class="group-call-join-btn">
                        <i class="fas fa-phone"></i> 参加する
                    </button>
                    <button id="groupCallResetBtn" class="group-call-reset-btn" title="繋がらない場合はここをタップ">
                        <i class="fas fa-rotate-right"></i>
                    </button>
                </div>
            `;
            const joinBtn = document.getElementById('groupCallJoinBtn');
            if (joinBtn) {
                joinBtn.addEventListener('click', () => {
                    // モーダルを閉じてから参加
                    if (this.el.groupModal) this.el.groupModal.classList.remove('visible');
                    this._joinActiveGroupCall(groupId);
                });
            }
            const resetBtn = document.getElementById('groupCallResetBtn');
            if (resetBtn) {
                resetBtn.addEventListener('click', () => this._resetStaleGroupCall(groupId));
            }
        }
    }

    // ゾンビ通話をリセットする（ホストが既に居ない／応答しない場合の手動リカバリー）
    async _resetStaleGroupCall(groupId) {
        const entry = this.activeGroupCalls.get(groupId);
        if (!entry) return;
        if (!confirm(`「${entry.hostName}」が開始した通話をリセットしますか？\n（実際にまだ通話中の場合、メンバーが切断されます）`)) return;
        try {
            const res = await FbAPI.forceClearGroupActiveCall(this.token, groupId);
            if (!res.ok) {
                this.showNotification('エラー', 'リセットに失敗しました: ' + (res.error || ''), 'error');
                return;
            }
            this.activeGroupCalls.delete(groupId);
            this._updateGroupCallBanner(groupId);
            this._refreshGroupListCallIndicator();
            this._updateGroupBadge();
            this.showNotification('通知', '通話をリセットしました', 'success', 2000);
        } catch (e) {
            this.showNotification('エラー', 'リセットに失敗しました', 'error');
        }
    }

    // グループ一覧の通話インジケータを更新する（行に🟢を付ける）
    _refreshGroupListCallIndicator() {
        if (!this.el.groupListArea) return;
        const rows = this.el.groupListArea.querySelectorAll('.dm-conv-item[data-gid]');
        rows.forEach(row => {
            const gid = row.dataset.gid;
            // 既存のインジケータを除去
            const existing = row.querySelector('.group-call-indicator');
            if (existing) existing.remove();
            if (this.activeGroupCalls.has(gid)) {
                const span = document.createElement('span');
                span.className = 'group-call-indicator';
                span.innerHTML = '<i class="fas fa-phone-volume"></i> 通話中';
                row.appendChild(span);
            }
        });
    }

    // [入口] 通話中に他のフレンドを追加招待
    async _inviteToMeshCall(targetName) {
        if (!this._meshIsInCall()) {
            this.showNotification('エラー', '通話中ではありません', 'error');
            return;
        }
        if (!this.friendNames.has(targetName)) {
            this.showNotification('通知', 'フレンドのみ招待できます', 'warning');
            return;
        }
        // グループ通話中は、グループメンバーのみ招待可
        if (this.meshGroupId) {
            const group = this.myGroups.find(g => g.id === this.meshGroupId);
            const isMember = !!group && Array.isArray(group.members) && group.members.includes(targetName);
            if (!isMember) {
                this.showNotification('通知', 'グループ通話ではグループメンバー以外を招待できません', 'warning');
                return;
            }
        }
        // 既に参加中なら何もしない
        for (const info of this.meshPeers.values()) {
            if (info.name === targetName) {
                this.showNotification('通知', `${targetName} は既に参加しています`, 'warning');
                return;
            }
        }
        if (targetName === this.myName) return;

        // ルームID = ホスト名（自分がホストでなければ this.meshHostName）
        const payload = encodeURIComponent(JSON.stringify({
            roomId: this.meshRoomId,
            hostName: this.meshHostName,
            inviterName: this.myName,
            isGroupCall: !!this.meshGroupId,
            groupId: this.meshGroupId || null,
            groupName: this.meshGroupName || null
        }));
        this.outgoingMeshInvitees.add(targetName);
        try {
            const res = await FbAPI.sendSignal(this.token, targetName, 'mesh_invite', payload);
            if (!res.ok) {
                this.outgoingMeshInvitees.delete(targetName);
                this.showNotification('エラー', '招待の送信に失敗: ' + (res.error || ''), 'error');
                return;
            }
            this.showNotification('招待', `${targetName} に招待を送信しました`, 'success', 2200);
            // 一定時間後に招待中リストから消す
            setTimeout(() => this.outgoingMeshInvitees.delete(targetName), 30000);
        } catch (e) {
            this.outgoingMeshInvitees.delete(targetName);
            this.showNotification('エラー', '招待の送信に失敗しました', 'error');
        }
    }

    // [シグナル受信] 招待が来た
    _onMeshInviteReceived(signal) {
        if (this.blockedUsers.has(signal.from)) {
            FbAPI.sendSignal(this.token, signal.from, 'mesh_invite_reject',
                encodeURIComponent(JSON.stringify({ reason: 'ブロックされています' }))).catch(() => { });
            return;
        }
        let payload;
        try { payload = JSON.parse(decodeURIComponent(signal.signal_data)); } catch (_) { return; }
        if (!payload || !payload.roomId || !payload.hostName) return;

        // 自分が既に通話中の場合
        if (this._meshIsInCall()) {
            // 同じルームの招待なら（多重招待）無視
            if (this.meshRoomId === payload.roomId) return;
            FbAPI.sendSignal(this.token, signal.from, 'mesh_invite_reject',
                encodeURIComponent(JSON.stringify({ reason: '通話中' }))).catch(() => { });
            return;
        }

        // グループ通話の招待の場合
        if (payload.isGroupCall) {
            // 自分がそのグループに所属していなければ拒否
            const group = this.myGroups.find(g => g.id === payload.groupId);
            const isMember = !!group && Array.isArray(group.members) && group.members.includes(this.myName);
            if (!isMember) {
                FbAPI.sendSignal(this.token, signal.from, 'mesh_invite_reject',
                    encodeURIComponent(JSON.stringify({ reason: 'グループメンバーではありません' }))).catch(() => { });
                return;
            }
            // 招待者もグループメンバーでなければ拒否
            const inviterIsMember = !!group && Array.isArray(group.members) && group.members.includes(signal.from);
            if (!inviterIsMember) {
                FbAPI.sendSignal(this.token, signal.from, 'mesh_invite_reject',
                    encodeURIComponent(JSON.stringify({ reason: '招待者がグループメンバーではありません' }))).catch(() => { });
                return;
            }
        } else {
            // 1対1招待: 招待元がフレンドであることを要求
            if (!this.friendNames.has(signal.from)) {
                FbAPI.sendSignal(this.token, signal.from, 'mesh_invite_reject',
                    encodeURIComponent(JSON.stringify({ reason: 'フレンド以外からの招待は受け付けません' }))).catch(() => { });
                return;
            }
        }

        // pending として保持
        this.pendingMeshInvite = { signal, payload };
        // モーダル表示
        this._showMeshIncomingCall(signal.from, payload);
    }

    _showMeshIncomingCall(fromName, payload) {
        this._resetIncomingCallButtons();
        this.el.incomingCallerName.textContent = payload.isGroupCall
            ? `${fromName} (グループ: ${payload.groupName || '...'})`
            : fromName;
        this.el.incomingCallModal.classList.add('visible');

        clearTimeout(this._meshIncomingTimeout);
        this._meshIncomingTimeout = setTimeout(() => {
            if (this.el.incomingCallModal.classList.contains('visible')) {
                this._rejectMeshIncomingCall();
            }
        }, 30000);
    }

    // [UI] 招待を承認
    async _acceptMeshIncomingCall() {
        if (this._incomingCallHandled) return;
        this._incomingCallHandled = true;

        const acceptBtn = this.el.acceptCallBtn;
        const rejectBtn = this.el.rejectCallBtn;
        acceptBtn.classList.add('processing');
        acceptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 接続中...';
        rejectBtn.disabled = true;

        clearTimeout(this._meshIncomingTimeout);

        const inv = this.pendingMeshInvite;
        this.pendingMeshInvite = null;
        if (!inv) {
            this._resetIncomingCallButtons();
            return;
        }

        this.el.incomingCallModal.classList.remove('visible');

        // 招待者に accept 通知（情報のみ）
        try {
            await FbAPI.sendSignal(this.token, inv.signal.from, 'mesh_invite_accept',
                encodeURIComponent(JSON.stringify({ roomId: inv.payload.roomId })));
        } catch (_) { }

        // メッシュ通話に参加（自分はゲスト）
        await this._startMeshCall({
            hostName: inv.payload.hostName,
            isHost: false,
            groupContext: inv.payload.isGroupCall
                ? { groupId: inv.payload.groupId, groupName: inv.payload.groupName }
                : null
        });

        this._resetIncomingCallButtons();
    }

    // [UI] 招待を拒否
    async _rejectMeshIncomingCall() {
        if (this._incomingCallHandled) return;
        this._incomingCallHandled = true;

        const acceptBtn = this.el.acceptCallBtn;
        const rejectBtn = this.el.rejectCallBtn;
        rejectBtn.classList.add('processing');
        rejectBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 拒否中...';
        acceptBtn.disabled = true;

        clearTimeout(this._meshIncomingTimeout);

        const inv = this.pendingMeshInvite;
        this.pendingMeshInvite = null;

        if (inv) {
            try {
                await FbAPI.sendSignal(this.token, inv.signal.from, 'mesh_invite_reject',
                    encodeURIComponent(JSON.stringify({ reason: '拒否' })));
            } catch (_) { }
        }

        this.el.incomingCallModal.classList.remove('visible');
        this._resetIncomingCallButtons();
    }

    // [シグナル受信] 招待拒否が来た
    _onMeshInviteRejected(signal) {
        let payload = {};
        try { payload = JSON.parse(decodeURIComponent(signal.signal_data)); } catch (_) { }
        // 1対1で呼び出し中なら通話を終了する
        if (this.outgoingMeshInvitees.has(signal.from)) {
            this.outgoingMeshInvitees.delete(signal.from);
        }
        // 呼び出し中モーダルが表示されていてかつ拒否されたのが対象者なら閉じる
        if (this.el.callingModal.classList.contains('visible') && this.callTargetName === signal.from) {
            clearTimeout(this._meshCallTimeout);
            this.el.callingModal.classList.remove('visible');
            this.showNotification('通知', `${signal.from} は通話を拒否しました${payload.reason ? `（${payload.reason}）` : ''}`, 'warning');
            // 自分以外まだ誰もいないなら通話を終了
            if (this.meshPeers.size === 0) {
                this._leaveMeshCall(true);
            }
        } else {
            this.showNotification('通知', `${signal.from} は通話を拒否しました${payload.reason ? `（${payload.reason}）` : ''}`, 'warning');
        }
    }

    _onMeshInviteAccepted(signal) {
        // 招待されたメンバーが acceptしたという通知のみ。実際の接続は相手から来る。
        // callingModalが出ていれば閉じる（1対1のケース）
        if (this.el.callingModal.classList.contains('visible') && this.callTargetName === signal.from) {
            clearTimeout(this._meshCallTimeout);
            const callingToEl = this.el.callingModal.querySelector('.calling-to');
            const cancelBtn = document.getElementById('cancelCallBtn');
            if (callingToEl) callingToEl.textContent = '接続中...';
            if (cancelBtn) cancelBtn.style.display = 'none';
            // 少し待ってモーダルを閉じる
            setTimeout(() => {
                this.el.callingModal.classList.remove('visible');
                if (callingToEl) callingToEl.textContent = '呼び出し中...';
                if (cancelBtn) cancelBtn.style.display = '';
            }, 800);
        }
    }

    _onMeshInviteCanceled(signal) {
        // 招待者がキャンセル
        if (this.pendingMeshInvite && this.pendingMeshInvite.signal.from === signal.from) {
            this.pendingMeshInvite = null;
            clearTimeout(this._meshIncomingTimeout);
            if (this.el.incomingCallModal.classList.contains('visible')) {
                this.el.incomingCallModal.classList.remove('visible');
                this.showNotification('通知', `${signal.from} が通話をキャンセルしました`, 'info');
            }
            this._resetIncomingCallButtons();
        }
    }

    // 呼び出し中（callingModal）のキャンセル
    async _cancelMeshOutgoingCall() {
        clearTimeout(this._meshCallTimeout);
        this.el.callingModal.classList.remove('visible');
        const targetName = this.callTargetName;
        if (targetName) {
            try {
                await FbAPI.sendSignal(this.token, targetName, 'mesh_invite_cancel',
                    encodeURIComponent(JSON.stringify({ roomId: this.meshRoomId })));
            } catch (_) { }
            this.outgoingMeshInvitees.delete(targetName);
        }
        this.callTargetName = null;
        // メッシュ通話自体も終了（まだ誰も参加していないので）
        if (this.meshPeers.size === 0) {
            await this._leaveMeshCall(true);
        }
    }

    // ====================================================
    // 招待モーダル（フレンド選択）
    // ====================================================
    showInviteFriendModal() {
        if (!this._meshIsInCall()) return;
        const modal = document.getElementById('meshInviteModal');
        if (!modal) return;

        // 既に参加中のメンバー
        const memberNames = new Set();
        memberNames.add(this.myName);
        this.meshPeers.forEach(info => { if (info.name && info.name !== '...') memberNames.add(info.name); });

        // 候補の絞り込み:
        // - グループ通話中: 「自分のフレンド ∩ そのグループのメンバー」
        // - 1対1通話中: 「自分のフレンド」全員
        // どちらも未参加かつブロック中ではない
        let candidates;
        if (this.meshGroupId) {
            const group = this.myGroups.find(g => g.id === this.meshGroupId);
            const groupMembers = new Set(group?.members || []);
            candidates = Array.from(this.friendNames).filter(name =>
                groupMembers.has(name) &&
                !memberNames.has(name) &&
                !this.blockedUsers.has(name)
            ).sort((a, b) => a.localeCompare(b, 'ja'));
        } else {
            candidates = Array.from(this.friendNames).filter(name =>
                !memberNames.has(name) && !this.blockedUsers.has(name)
            ).sort((a, b) => a.localeCompare(b, 'ja'));
        }

        // モーダル見出しの文言切替
        const headerTitle = modal.querySelector('.mesh-invite-header h2');
        const desc = modal.querySelector('.mesh-invite-desc');
        if (this.meshGroupId) {
            if (headerTitle) headerTitle.innerHTML = '<i class="fas fa-user-plus"></i> グループメンバーを招待';
            if (desc) desc.textContent = 'グループに所属していて、まだ参加していないメンバーを招待できます。';
        } else {
            if (headerTitle) headerTitle.innerHTML = '<i class="fas fa-user-plus"></i> 通話に招待';
            if (desc) desc.textContent = 'フレンドの中から、まだ参加していない人を招待できます。';
        }

        const list = document.getElementById('meshInviteList');
        if (list) {
            if (candidates.length === 0) {
                const emptyMsg = this.meshGroupId
                    ? '招待できるグループメンバーがいません'
                    : '招待できるフレンドがいません';
                list.innerHTML = `<div class="mesh-invite-empty"><i class="fas fa-user-slash"></i><p>${emptyMsg}</p></div>`;
            } else {
                list.innerHTML = candidates.map(name => {
                    const av = this.avatarCache?.[name];
                    const avatarHTML = av
                        ? `<img class="mesh-invite-avatar" src="${av}" alt="">`
                        : `<div class="mesh-invite-avatar mesh-invite-avatar-letter">${this._escapeHtml(name.charAt(0).toUpperCase())}</div>`;
                    const isPending = this.outgoingMeshInvitees.has(name);
                    return `
                        <div class="mesh-invite-row" data-invite-name="${this._escapeHtml(name)}">
                            ${avatarHTML}
                            <div class="mesh-invite-name">${this._escapeHtml(name)}</div>
                            <button class="mesh-invite-btn" ${isPending ? 'disabled' : ''}>
                                <i class="fas fa-paper-plane"></i> ${isPending ? '招待済' : '招待'}
                            </button>
                        </div>
                    `;
                }).join('');
                // イベントを付与
                list.querySelectorAll('.mesh-invite-row').forEach(row => {
                    const btn = row.querySelector('.mesh-invite-btn');
                    if (!btn || btn.disabled) return;
                    btn.addEventListener('click', async () => {
                        const name = row.dataset.inviteName;
                        btn.disabled = true;
                        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 送信中';
                        await this._inviteToMeshCall(name);
                        btn.innerHTML = '<i class="fas fa-check"></i> 招待済';
                    });
                });
            }
        }
        modal.classList.add('visible');
    }

    hideInviteFriendModal() {
        const modal = document.getElementById('meshInviteModal');
        if (modal) modal.classList.remove('visible');
    }

    // ====================================================
    // ヘルパー: HTMLエスケープ
    // ====================================================
    _escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // ====================================================
    // ユーザー名の予測候補（カスタムドロップダウン）
    // - 全アカウントを取得してキャッシュ
    // - 入力にマッチする名前を絞り込み（部分一致・ひらがな/カタカナ変換対応）
    // ====================================================

    // 全アカウント一覧を取得してキャッシュ。getOnlineで取れるのはオンラインだけなので
    // ここでは accounts ノードから全名を取得する
    async _loadAllAccountNamesForSuggest() {
        if (this._allAccountNamesFetching) return this._allAccountNamesFetching;
        this._allAccountNamesFetching = (async () => {
            try {
                const names = await FbAPI.getAllAccountNames();
                this._allAccountNames = names || [];
            } catch (_) {
                this._allAccountNames = this._allAccountNames || [];
            }
        })();
        await this._allAccountNamesFetching;
        this._allAccountNamesFetching = null;
        this._allAccountNamesFetchedAt = Date.now();
        return this._allAccountNames;
    }

    // 必要なら再取得する
    async _ensureAllAccountNames() {
        const STALE_MS = 60 * 1000; // 60秒キャッシュ
        if (!this._allAccountNames || !this._allAccountNamesFetchedAt ||
            (Date.now() - this._allAccountNamesFetchedAt) > STALE_MS) {
            await this._loadAllAccountNamesForSuggest();
        }
        return this._allAccountNames || [];
    }

    // カタカナ→ひらがな変換（U+30A1〜U+30F6 を 0x60引いてひらがな化）
    _toHiragana(s) {
        return String(s || '').replace(/[\u30a1-\u30f6]/g, ch =>
            String.fromCharCode(ch.charCodeAt(0) - 0x60));
    }

    // ひらがな→カタカナ
    _toKatakana(s) {
        return String(s || '').replace(/[\u3041-\u3096]/g, ch =>
            String.fromCharCode(ch.charCodeAt(0) + 0x60));
    }

    // 文字列正規化: 小文字化＋ひらがな化（マッチングに使う）
    _normalizeForMatch(s) {
        return this._toHiragana(String(s || '').toLowerCase().normalize('NFKC'));
    }

    // 入力欄に対しサジェストポップアップを表示する
    _showUserSuggest(inputEl) {
        const popup = document.getElementById('userSuggestionPopup');
        if (!popup || !inputEl) return;

        const query = inputEl.value || '';
        const normalizedQuery = this._normalizeForMatch(query);

        // 候補リスト準備
        const allNames = (this._allAccountNames || []).filter(n => n && n !== this.myName);
        const blocked = this.blockedUsers || new Set();

        // 「親しい人」の集合（フレンド/グループメンバー/DM相手）
        const friendSet = this.friendNames || new Set();
        const familiar = new Set();
        friendSet.forEach(n => familiar.add(n));
        if (Array.isArray(this.myGroups)) {
            for (const g of this.myGroups) {
                if (Array.isArray(g.members)) for (const m of g.members) familiar.add(m);
            }
        }
        if (this.localChatDB) {
            for (const key of Object.keys(this.localChatDB)) {
                if (key.startsWith('dm:')) {
                    const pair = key.slice(3).split('|');
                    for (const p of pair) {
                        if (p && p !== this.myName) familiar.add(p);
                    }
                }
            }
        }

        // フィルタリング
        let filtered;
        if (normalizedQuery === '') {
            // 空入力時: 「親しい人」を優先表示
            filtered = allNames.filter(n => familiar.has(n));
        } else {
            filtered = allNames.filter(n => {
                const norm = this._normalizeForMatch(n);
                return norm.includes(normalizedQuery);
            });
        }

        // 並び替え: 完全一致 > 前方一致 > 中間一致、各内で「親しい人優先」「辞書順」
        filtered.sort((a, b) => {
            const na = this._normalizeForMatch(a);
            const nb = this._normalizeForMatch(b);
            const ra = na === normalizedQuery ? 0 : (na.startsWith(normalizedQuery) ? 1 : 2);
            const rb = nb === normalizedQuery ? 0 : (nb.startsWith(normalizedQuery) ? 1 : 2);
            if (ra !== rb) return ra - rb;
            const fa = familiar.has(a) ? 0 : 1;
            const fb = familiar.has(b) ? 0 : 1;
            if (fa !== fb) return fa - fb;
            return a.localeCompare(b, 'ja');
        });

        // 最大8件
        filtered = filtered.slice(0, 8);

        if (filtered.length === 0) {
            popup.innerHTML = `<div class="user-suggest-empty">候補がありません</div>`;
        } else {
            popup.innerHTML = filtered.map(n => {
                const av = this.avatarCache?.[n];
                const avatarHTML = av
                    ? `<img class="user-suggest-avatar" src="${av}" alt="">`
                    : `<div class="user-suggest-avatar user-suggest-avatar-letter">${this._escapeHtml(n.charAt(0).toUpperCase())}</div>`;
                const isFamiliar = familiar.has(n);
                const tag = friendSet.has(n)
                    ? '<span class="user-suggest-tag friend">フレンド</span>'
                    : (isFamiliar ? '<span class="user-suggest-tag known">既知</span>' : '');
                // ハイライト: クエリ部分を <strong> で
                let displayName;
                if (normalizedQuery) {
                    const norm = this._normalizeForMatch(n);
                    const idx = norm.indexOf(normalizedQuery);
                    if (idx >= 0) {
                        const before = this._escapeHtml(n.slice(0, idx));
                        const match = this._escapeHtml(n.slice(idx, idx + normalizedQuery.length));
                        const after = this._escapeHtml(n.slice(idx + normalizedQuery.length));
                        displayName = `${before}<mark>${match}</mark>${after}`;
                    } else {
                        displayName = this._escapeHtml(n);
                    }
                } else {
                    displayName = this._escapeHtml(n);
                }
                return `
                    <div class="user-suggest-item" data-name="${this._escapeHtml(n)}">
                        ${avatarHTML}
                        <span class="user-suggest-name">${displayName}</span>
                        ${tag}
                    </div>
                `;
            }).join('');
            // クリックハンドラ
            popup.querySelectorAll('.user-suggest-item').forEach(item => {
                item.addEventListener('mousedown', (e) => {
                    e.preventDefault(); // blurされない
                    inputEl.value = item.dataset.name;
                    this._hideUserSuggest();
                    // input イベントを発火（バリデーションなどに反応させる）
                    inputEl.dispatchEvent(new Event('input', { bubbles: true }));
                });
            });
        }

        // 位置を入力欄の直下に
        const rect = inputEl.getBoundingClientRect();
        popup.style.display = '';
        popup.style.left = rect.left + 'px';
        popup.style.top = (rect.bottom + window.scrollY + 4) + 'px';
        popup.style.width = Math.max(rect.width, 240) + 'px';
        this._suggestActiveInput = inputEl;
    }

    _hideUserSuggest() {
        const popup = document.getElementById('userSuggestionPopup');
        if (popup) popup.style.display = 'none';
        this._suggestActiveInput = null;
    }

    // 入力欄にサジェストを bind する
    _bindSuggestInput(inp) {
        if (!inp || inp._suggestBound) return;
        inp._suggestBound = true;
        inp.addEventListener('focus', async () => {
            await this._ensureAllAccountNames();
            this._showUserSuggest(inp);
        });
        inp.addEventListener('input', () => {
            this._showUserSuggest(inp);
        });
        inp.addEventListener('blur', () => {
            // クリック処理が走るまで少し待ってから閉じる
            setTimeout(() => this._hideUserSuggest(), 150);
        });
        // Enter キーは既存ハンドラに任せる
    }
}

// =====================================================
// エントリポイント
// =====================================================
window.addEventListener('DOMContentLoaded', () => {
    new SecureVideoChat();
});