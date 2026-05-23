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
                    groups.push({ id: gid, name: g.name, owner: g.owner, members, avatar: g.avatar || null });
                }
            }
        }
        return { ok: true, groups };
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
        this.isVideoEnabled = true;
        this.isMediaReady = false;
        this.audioContext = null;
        this.gainNode = null;
        this.currentVolume = 100;
        this.disconnectedBySelf = false;
        this.isDisconnecting = false;
        this.isVolumeControlVisible = false;
        this.isKeyVisible = false;

        // メッシュ通話（複数人）
        this.MESH_MAX_PARTICIPANTS = 8; // 自分を含めて最大8人
        this.callMode = null; // null | 'one-to-one' | 'mesh'
        this.meshRoomId = null;
        this.meshOriginGroupId = null; // グループ通話の場合、起点となるグループID
        this.meshPeers = new Map(); // peerId -> { call, conn, name, stream, micOn, camOn }
        this.meshIsHost = false;
        this.meshHostPeerId = null;
        this.pendingMeshInvite = null; // 受信した mesh_invite
        this.activeGroupCalls = new Map(); // groupId -> { roomId, hostName, hostPeerId, participants:[names], startedAt }
        this._processedMeshInvites = new Set(); // 同じ招待を二重に出さないため

        // シグナリング
        this.heartbeatInterval = null;
        this.onlineListInterval = null;
        this.pendingSignal = null;
        this.callTargetName = null;
        this._processedSignalIds = new Set();

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

            // メッシュ通話
            meshGrid: document.getElementById('meshGrid'),
            meshInviteBtn: document.getElementById('meshInviteBtn'),
            meshMicBtn: document.getElementById('meshMicBtn'),
            meshCamBtn: document.getElementById('meshCamBtn'),
            groupCallStartBtn: document.getElementById('groupCallStartBtn'),
            groupActiveCallBanner: document.getElementById('groupActiveCallBanner'),
            groupActiveCallSub: document.getElementById('groupActiveCallSub'),
            groupActiveCallJoinBtn: document.getElementById('groupActiveCallJoinBtn'),
            meshInviteModal: document.getElementById('meshInviteModal'),
            meshInviteFrom: document.getElementById('meshInviteFrom'),
            meshInviteMembers: document.getElementById('meshInviteMembers'),
            acceptMeshInviteBtn: document.getElementById('acceptMeshInviteBtn'),
            rejectMeshInviteBtn: document.getElementById('rejectMeshInviteBtn'),
            meshInviteSelectModal: document.getElementById('meshInviteSelectModal'),
            meshInviteCandidateList: document.getElementById('meshInviteCandidateList'),
            meshInviteSelectCancelBtn: document.getElementById('meshInviteSelectCancelBtn'),
            meshInviteSlotInfo: document.getElementById('meshInviteSlotInfo'),
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
        FbAPI.getGroups(this.token).then(res => {
            if (res?.ok) {
                this.myGroups = res.groups || [];
                for (const g of this.myGroups) {
                    if (g.avatar) this.groupAvatarCache[g.id] = g.avatar;
                }
                this._recomputeAllUnreadBadges();
            }
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
            // メッシュ通話中ならメッシュ用退出処理
            if (this.callMode === 'mesh') {
                this._leaveMeshCall();
                return;
            }
            if (this.isDisconnecting) return;
            this.el.disconnectButton.disabled = true;
            this.el.disconnectButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 切断中...';
            this.disconnectedBySelf = true;
            this.sendDisconnectSignal().then(() => {
                this.showDisconnectOverlay('通話を終了しました');
                this.disconnect();
            });
        });
        this.el.toggleMicButton.addEventListener('click', () => this.toggleAudio());
        this.el.toggleVideoButton.addEventListener('click', () => this.toggleVideo());
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
                const onlineEl = this.el.userList.querySelector(`[data-name="${CSS.escape(this.dmPartner)}"]`);
                const peerId = onlineEl?.dataset.peerId;
                if (peerId) this.startOutgoingCall(this.dmPartner, peerId);
                else this.showNotification('通知', '相手がオフラインです', 'warning');
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

        // メッシュ通話: グループ通話開始
        if (this.el.groupCallStartBtn) this.el.groupCallStartBtn.addEventListener('click', () => this._startGroupCall());
        // 通話中バナーから「参加する」
        if (this.el.groupActiveCallJoinBtn) this.el.groupActiveCallJoinBtn.addEventListener('click', () => this._joinActiveGroupCall());
        // メッシュ通話: 招待モーダル（受信側）
        if (this.el.acceptMeshInviteBtn) this.el.acceptMeshInviteBtn.addEventListener('click', () => this._handleMeshInvite(true));
        if (this.el.rejectMeshInviteBtn) this.el.rejectMeshInviteBtn.addEventListener('click', () => this._handleMeshInvite(false));
        // メッシュ通話: 通話中の「招待」ボタン
        if (this.el.meshInviteBtn) this.el.meshInviteBtn.addEventListener('click', () => this._openMeshInviteSelectModal());
        if (this.el.meshInviteSelectCancelBtn) this.el.meshInviteSelectCancelBtn.addEventListener('click', () => this.el.meshInviteSelectModal.classList.remove('visible'));
        // メッシュ通話: マイク・カメラ制御
        if (this.el.meshMicBtn) this.el.meshMicBtn.addEventListener('click', () => this._toggleMeshMic());
        if (this.el.meshCamBtn) this.el.meshCamBtn.addEventListener('click', () => this._toggleMeshCam());

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
                    // 1対1通話中も「招待」ボタンを表示
                    if (this.el.meshInviteBtn) this.el.meshInviteBtn.style.display = '';
                    if (this.el.meshMicBtn) this.el.meshMicBtn.style.display = 'none';
                    if (this.el.meshCamBtn) this.el.meshCamBtn.style.display = 'none';
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
                // トラックを有効化し直す（無効化されていた場合に備えて）
                this.localStream.getAudioTracks().forEach(t => t.enabled = this.isAudioEnabled !== false);
                this.localStream.getVideoTracks().forEach(t => t.enabled = this.isVideoEnabled !== false);
                if (this.el.localVideo) {
                    if (this.el.localVideo.srcObject !== this.localStream) {
                        this.el.localVideo.srcObject = this.localStream;
                    }
                    this.el.localVideo.style.display = '';
                }
                this.isMediaReady = true;
                return;
            }
        }
        this.updateStatus('カメラ/マイク準備中...');
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
            this.el.localVideo.srcObject = this.localStream;
            this.isMediaReady = true;
        } catch (e) {
            console.warn('カメラ/マイクの許可が得られませんでした:', e);
            this.localStream = null;
            this.isMediaReady = false;
            if (this.el.localVideo) this.el.localVideo.style.display = 'none';
        }
        this.updateStatus('オンライン');
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
        FbAPI.subscribeSignals(this.myName, async (signal) => {
            // 処理済みシグナルは無視
            if (this._processedSignalIds.has(signal.id)) {
                await FbAPI.ackSignal(this.token, signal.id, this.myName);
                return;
            }
            this._processedSignalIds.add(signal.id);
            try {
                await this.handleSignal(signal);
            } catch (e) {
                console.warn('handleSignalエラー:', e);
            }
            // シグナル処理後は削除（ack相当）
            await FbAPI.ackSignal(this.token, signal.id, this.myName);
            if (this._processedSignalIds.size > 200) {
                const it = this._processedSignalIds.values();
                this._processedSignalIds.delete(it.next().value);
            }
        });
    }

    async handleSignal(signal) {
        console.log('[シグナル受信]', signal);
        switch (signal.type) {
            case 'call_request':
                if (this.currentCall) {
                    await FbAPI.sendSignal(this.token, signal.from, 'call_reject', '通話中');
                    return;
                }
                if (this.el.callingModal.classList.contains('visible') && this.callTargetName === signal.from) {
                    console.log('[同時発信] 相手も同時に発信していたため自動接続:', signal.from);
                    clearTimeout(this._callTimeout);
                    const callingToEl = this.el.callingModal.querySelector('.calling-to');
                    const cancelBtn = document.getElementById('cancelCallBtn');
                    if (callingToEl) callingToEl.textContent = '接続中...';
                    if (cancelBtn) cancelBtn.style.display = 'none';
                    try {
                        await FbAPI.sendSignal(this.token, signal.from, 'call_accept', this.peer.id);
                    } catch (_) { }
                    if (this.myName < signal.from) {
                        this.initiateWebRTCCall(signal.signal_data);
                    }
                    return;
                }
                if (this.pendingSignal) {
                    return;
                }
                this.showIncomingCall(signal);
                break;

            case 'call_accept':
                if (!this.el.callingModal.classList.contains('visible')) return;
                clearTimeout(this._callTimeout);
                {
                    const callingToEl = this.el.callingModal.querySelector('.calling-to');
                    const cancelBtn = document.getElementById('cancelCallBtn');
                    if (callingToEl) callingToEl.textContent = '接続中...';
                    if (cancelBtn) cancelBtn.style.display = 'none';
                }
                console.log('[call_accept] 相手ピアID:', signal.signal_data);
                this.initiateWebRTCCall(signal.signal_data);
                break;

            case 'call_reject':
                if (!this.el.callingModal.classList.contains('visible')) return;
                clearTimeout(this._callTimeout);
                this.el.callingModal.classList.remove('visible');
                this.callTargetName = null;
                this.showNotification('通知', `${signal.from} は通話を拒否しました`, 'warning');
                break;

            case 'call_end':
                if (!this.isDisconnecting) {
                    this.handleRemoteDisconnect(`${signal.from} が通話を終了しました`);
                }
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

            case 'name_changed':
                // 相手が名前を変えた: ローカルDM履歴のキーを旧名→新名にマージする
                try {
                    const nc = JSON.parse(decodeURIComponent(signal.signal_data));
                    if (nc && nc.oldName && nc.newName) {
                        this._handlePartnerNameChanged(nc.oldName, nc.newName);
                    }
                } catch (_) { }
                break;

            // ===== メッシュ通話（複数人通話）関連 =====
            case 'group_call_notify':
                // グループ通話が開始された通知（メンバー全員に届く）
                try {
                    const gd = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._receiveGroupCallNotify(signal.from, gd);
                } catch (_) { }
                break;

            case 'group_call_end_notify':
                // グループ通話が終了した通知
                try {
                    const gd = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._receiveGroupCallEndNotify(gd);
                } catch (_) { }
                break;

            case 'mesh_invite':
                // 1対1通話中の第三者招待（または明示的なメッシュ通話招待）
                if (this.blockedUsers.has(signal.from)) break;
                try {
                    const inv = JSON.parse(decodeURIComponent(signal.signal_data));
                    this._showMeshInvite(signal.from, inv);
                } catch (_) { }
                break;

            case 'mesh_invite_reject':
                // 招待した相手が拒否した通知
                this.showNotification('通知', `${signal.from} は招待を拒否しました`, 'warning');
                break;
        }
    }

    // =====================================================
    // 発信
    // =====================================================
    async startOutgoingCall(targetName, targetPeerId) {
        if (this.currentCall) {
            this.showNotification('通知', '現在通話中です', 'warning');
            return;
        }
        // フレンドのみ通話可能
        if (!this.friendNames.has(targetName)) {
            this.showNotification('通知', 'フレンドのみ通話できます。先にフレンド申請を送ってください。', 'warning');
            return;
        }
        if (!targetPeerId) {
            this.showNotification('エラー', '相手のピアIDが取得できませんでした。リストを更新してください。', 'error');
            return;
        }
        if (!this.peer || !this.peer.id) {
            this.showNotification('エラー', '接続の準備が完了していません。しばらく待ってから再試行してください。', 'error');
            return;
        }

        if (!this.localStream) {
            await this.setupLocalStream();
            if (!this.isMediaReady) {
                this.showNotification('通知', 'カメラ・マイクが利用できません。音声・映像なしで通話します。', 'warning');
            }
        }

        this.callTargetName = targetName;
        this._targetPeerId = targetPeerId;
        this.el.callingTargetName.textContent = targetName;
        this.el.callingModal.classList.add('visible');

        try {
            const myPeerId = this.peer.id;
            console.log('[発信] to:', targetName, 'myPeerId:', myPeerId);
            const res = await FbAPI.sendSignal(this.token, targetName, 'call_request', myPeerId);
            if (!res.ok) {
                this.el.callingModal.classList.remove('visible');
                this.showNotification('エラー', '通話申請の送信に失敗しました: ' + (res.error || ''), 'error');
                return;
            }
        } catch (e) {
            this.el.callingModal.classList.remove('visible');
            this.showNotification('エラー', '通話申請の送信に失敗しました', 'error');
            return;
        }

        this._callTimeout = setTimeout(() => {
            if (this.el.callingModal.classList.contains('visible')) {
                this.el.callingModal.classList.remove('visible');
                this.callTargetName = null;
                this.showNotification('通知', '通話申請がタイムアウトしました', 'warning');
            }
        }, 30000);
    }

    async cancelOutgoingCall() {
        clearTimeout(this._callTimeout);
        this.el.callingModal.classList.remove('visible');
        if (this.callTargetName) {
            try {
                await FbAPI.sendSignal(this.token, this.callTargetName, 'call_reject', 'キャンセル');
            } catch (_) { }
        }
        this.callTargetName = null;
    }

    initiateWebRTCCall(remotePeerId) {
        if (!remotePeerId) return;

        this.el.callingModal.classList.remove('visible');
        const callingToEl = this.el.callingModal.querySelector('.calling-to');
        const cancelBtn = document.getElementById('cancelCallBtn');
        if (callingToEl) callingToEl.textContent = '呼び出し中...';
        if (cancelBtn) cancelBtn.style.display = '';

        this.el.remoteName.textContent = this.callTargetName || '相手';
        this.el.videoGrid.style.display = '';
        this.el.waitingState.style.display = 'none';
        this.el.callControls.style.display = '';
        // 1対1通話中も「招待」ボタンを表示（メッシュ昇格機能）
        if (this.el.meshInviteBtn) this.el.meshInviteBtn.style.display = '';
        // 1対1のときはメッシュ用マイク・カメラボタンは非表示
        if (this.el.meshMicBtn) this.el.meshMicBtn.style.display = 'none';
        if (this.el.meshCamBtn) this.el.meshCamBtn.style.display = 'none';
        this.showUserListSection(false);

        this.dataConnection = this.peer.connect(remotePeerId);
        this.setupDataConnection();

        const call = this.peer.call(remotePeerId, this.localStream || undefined);
        this.handleCall(call);
    }

    showIncomingCall(signal) {
        if (this.blockedUsers.has(signal.from)) {
            FbAPI.sendSignal(this.token, signal.from, 'call_reject', 'ブロックされています').catch(() => { });
            return;
        }
        // フレンドのみ通話可能（常時強制）
        if (!this.friendNames.has(signal.from)) {
            FbAPI.sendSignal(this.token, signal.from, 'call_reject', 'フレンド以外の通話を受け付けていません').catch(() => { });
            return;
        }
        this.pendingSignal = signal;
        this._resetIncomingCallButtons();
        this.el.incomingCallerName.textContent = signal.from;
        this.el.incomingCallModal.classList.add('visible');

        this._incomingTimeout = setTimeout(() => {
            if (this.el.incomingCallModal.classList.contains('visible')) {
                this.rejectIncomingCall();
            }
        }, 30000);
    }

    async acceptIncomingCall() {
        if (this._incomingCallHandled) return;
        this._incomingCallHandled = true;

        const acceptBtn = this.el.acceptCallBtn;
        const rejectBtn = this.el.rejectCallBtn;
        acceptBtn.classList.add('processing');
        acceptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 受諾中...';
        rejectBtn.disabled = true;

        clearTimeout(this._incomingTimeout);

        if (!this.pendingSignal) {
            this._incomingCallHandled = false;
            acceptBtn.classList.remove('processing');
            acceptBtn.innerHTML = '<i class="fas fa-phone"></i> 応答する';
            rejectBtn.disabled = false;
            return;
        }
        const signal = this.pendingSignal;
        this.pendingSignal = null;

        console.log('[着信承認] 発信者ピアID:', signal.signal_data, '発信者名:', signal.from);

        this.callTargetName = signal.from;
        this.el.remoteName.textContent = signal.from;

        if (!this.localStream) {
            await this.setupLocalStream();
            if (!this.isMediaReady) {
                this.showNotification('通知', 'カメラ・マイクが利用できません。音声・映像なしで通話します。', 'warning');
            }
        }

        try {
            await FbAPI.sendSignal(this.token, signal.from, 'call_accept', this.peer.id);
        } catch (e) {
            this.showNotification('エラー', '応答シグナルの送信に失敗しました', 'error');
            this._incomingCallHandled = false;
            acceptBtn.classList.remove('processing');
            acceptBtn.innerHTML = '<i class="fas fa-phone"></i> 応答する';
            rejectBtn.disabled = false;
            return;
        }

        acceptBtn.classList.remove('processing');
        acceptBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 接続待機中...';
        acceptBtn.disabled = true;
        rejectBtn.disabled = true;

        console.log('[着信承認完了] 発信者からのWebRTC着信を待機中...');
    }

    async rejectIncomingCall() {
        if (this._incomingCallHandled) return;
        this._incomingCallHandled = true;

        const acceptBtn = this.el.acceptCallBtn;
        const rejectBtn = this.el.rejectCallBtn;
        rejectBtn.classList.add('processing');
        rejectBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 拒否中...';
        acceptBtn.disabled = true;

        clearTimeout(this._incomingTimeout);

        if (!this.pendingSignal) {
            this._incomingCallHandled = false;
            rejectBtn.classList.remove('processing');
            rejectBtn.innerHTML = '<i class="fas fa-phone-slash"></i> 拒否する';
            acceptBtn.disabled = false;
            return;
        }
        const signal = this.pendingSignal;
        this.pendingSignal = null;

        try {
            await FbAPI.sendSignal(this.token, signal.from, 'call_reject', '拒否');
        } catch (_) { }

        this.el.incomingCallModal.classList.remove('visible');
        rejectBtn.classList.remove('processing');
        rejectBtn.innerHTML = '<i class="fas fa-phone-slash"></i> 拒否する';
        acceptBtn.disabled = false;
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
    // WebRTC通話処理
    // =====================================================
    handleCall(call) {
        this.currentCall = call;
        this.callMode = 'one-to-one';

        call.on('stream', stream => {
            this.el.remoteVideo.srcObject = stream;
            this.setupAudioBoost(stream);
            this.updateStatus('通話中');
            this.startConnectionQualityMonitoring();
        });

        call.on('close', () => {
            if (this.isDisconnecting) return;
            // 昇格中なら切断扱いしない
            if (this._upgradingToMesh) {
                return;
            }
            this.handleRemoteDisconnect('相手が通話を終了しました');
        });

        call.peerConnection.oniceconnectionstatechange = () => {
            this.updateConnectionQuality(call.peerConnection.iceConnectionState);
        };
    }

    setupDataConnection() {
        this.dataConnection.on('open', () => {
            this.updateStatus('通話中');
        });

        this.dataConnection.on('data', async data => {
            if (data && data.type === 'DISCONNECT_SIGNAL') {
                if (!this.isDisconnecting) {
                    this.handleRemoteDisconnect('相手が通話を終了しました');
                }
                return;
            }
            // 相手が「これからメッシュ通話に昇格する」と通知してきた場合：
            // 切断扱いしない（mesh_inviteシグナルが別途届いて自動移行する）
            if (data && data.type === 'UPGRADE_TO_MESH') {
                this._upgradingToMesh = true;
                return;
            }
            try {
                const decrypted = await CryptoUtil.decrypt(this.encryptionKey, data.iv, data.encryptedData);
                this.handleReceivedData(JSON.parse(new TextDecoder().decode(decrypted)));
            } catch (_) { }
        });

        this.dataConnection.on('close', () => {
            if (this.isDisconnecting) return;
            // 昇格中なら切断扱いしない（メッシュへ移行する）
            if (this._upgradingToMesh) {
                this._upgradingToMesh = false;
                return;
            }
            this.handleRemoteDisconnect('相手が通話を終了しました');
        });
    }

    handleRemoteDisconnect(reason) {
        if (this.isDisconnecting) return;
        if (this._remoteDisconnectHandled) return;
        this._remoteDisconnectHandled = true;
        if (!this.currentCall && !this.dataConnection) return;
        this.showDisconnectOverlay(reason);
        this.disconnect();
    }

    async sendDisconnectSignal() {
        if (this.dataConnection && this.dataConnection.open !== false) {
            try {
                this.dataConnection.send({ type: 'DISCONNECT_SIGNAL' });
                await new Promise(r => setTimeout(r, 150));
            } catch (_) { }
        }
        if (this.token && this.el.remoteName.textContent) {
            try {
                await FbAPI.sendSignal(this.token, this.el.remoteName.textContent, 'call_end', '');
            } catch (_) { }
        }
    }

    async disconnect() {
        if (this.isDisconnecting) return;
        this.isDisconnecting = true;

        if (this._qualityInterval) {
            clearInterval(this._qualityInterval);
            this._qualityInterval = null;
        }

        await this.cleanup();

        this.el.videoGrid.style.display = 'none';
        this.el.waitingState.style.display = '';
        this.el.callControls.style.display = 'none';
        // メッシュ通話関連UIのクリア
        if (this.el.meshInviteBtn) this.el.meshInviteBtn.style.display = 'none';
        if (this.el.meshMicBtn) this.el.meshMicBtn.style.display = 'none';
        if (this.el.meshCamBtn) this.el.meshCamBtn.style.display = 'none';
        this.callMode = null;
        this.showUserListSection(true);

        if (this.audioContext) {
            try { this.audioContext.close(); } catch (_) { }
            this.audioContext = null;
            this.gainNode = null;
            this.preGainNode = null;
            this.compressorNode = null;
            this.makeUpGainNode = null;
            this.audioSource = null;
        }
        this.el.remoteVideo.muted = false;
        this.isVolumeControlVisible = false;
        if (this.el.volumeSliderContainer) this.el.volumeSliderContainer.classList.remove('visible');
        // 音量を100%にリセットし、スライダーとUI（バー色・BOOSTバッジ・数値）も完全リセット
        this.currentVolume = 100;
        if (this.el.volumeSlider) this.el.volumeSlider.value = 100;
        this._refreshVolumeUI(100);
        this.updateStatus('オンライン');

        this.disconnectedBySelf = false;
        this.isDisconnecting = false;
        this.callTargetName = null;

        if (this.el.disconnectButton) {
            this.el.disconnectButton.disabled = false;
            this.el.disconnectButton.innerHTML = '<i class="fas fa-phone-slash"></i> 通話を終了';
        }

        setTimeout(() => {
            this._remoteDisconnectHandled = false;
            this._incomingCallHandled = false;
        }, 1000);

        try {
            await this.initializePeer();
            // localStream は破棄せず保持。次回の通話で再利用してカメラ・マイクの許可を再要求しない
            if (this.el.localVideo) {
                this.el.localVideo.style.display = '';
                // 保持しているストリームを再アタッチして表示
                if (this.localStream && this.el.localVideo.srcObject !== this.localStream) {
                    this.el.localVideo.srcObject = this.localStream;
                }
            }
        } catch (e) {
            console.warn('再初期化失敗:', e);
        }

        await this.refreshOnlineList();
    }

    showUserListSection(visible) {
        const section = document.querySelector('.user-list-section') || this.el.userList?.closest('section') || this.el.userList?.parentElement;
        if (section) section.style.display = visible ? '' : 'none';
        const mainLayout = document.querySelector('.main-layout');
        if (mainLayout) mainLayout.classList.toggle('in-call', !visible);
    }

    async cleanup() {
        const call = this.currentCall;
        const dc = this.dataConnection;
        const peer = this.peer;

        this.currentCall = null;
        this.dataConnection = null;
        this.peer = null;
        // localStream は保持してカメラ・マイクの再取得を不要にする

        if (call) { try { call.close(); } catch (_) { } }
        if (dc) { try { dc.close(); } catch (_) { } }
        if (peer) { try { peer.destroy(); } catch (_) { } }

        if (this.el.remoteVideo) this.el.remoteVideo.srcObject = null;
        // localVideo.srcObject は保持（ストリーム再利用のため）
    }

    handleReceivedData(data) {
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
        if (keys.length > 50) keys.slice(0, keys.length - 50).forEach(k => delete this.localChatDB[k]);
        Object.keys(this.localChatDB).forEach(k => {
            if (this.localChatDB[k].length > 200) this.localChatDB[k] = this.localChatDB[k].slice(-200);
        });
        localStorage.setItem('svc_chat_db', JSON.stringify(this.localChatDB));
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
        return true;
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
    _startNewDm() {
        const name = this.el.newDmTargetName?.value.trim();
        if (this.el.newDmError) this.el.newDmError.textContent = '';
        if (!name) { if (this.el.newDmError) this.el.newDmError.textContent = '名前を入力してください'; return; }
        if (name === this.myName) { if (this.el.newDmError) this.el.newDmError.textContent = '自分とはDMできません'; return; }
        if (this.blockedUsers.has(name)) { if (this.el.newDmError) this.el.newDmError.textContent = 'ブロック中のユーザーです'; return; }
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
        this.el.groupModal.classList.add('visible');
        await this._loadGroups();
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
            }
        } catch (_) { }
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
            const isActiveCall = this.activeGroupCalls.has(g.id);
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
            const callBadge = isActiveCall ? `<span class="group-active-call-badge"><i class="fas fa-phone-volume"></i>通話中</span>` : '';
            return `<div class="dm-conv-item" data-gid="${this.escapeHtml(g.id)}" data-gname="${this.escapeHtml(g.name)}">
                ${avatarHtml}
                <div class="dm-conv-info">
                    <span class="dm-conv-name">${this.escapeHtml(g.name)}${callBadge}</span>
                    <span class="dm-conv-preview">${g.members ? this.escapeHtml(g.members.join(', ')) : ''}</span>
                </div>
                ${unread > 0 ? `<span class="dm-unread-badge">${unread}</span>` : ''}
            </div>`;
        }).join('');
        this.el.groupListArea.querySelectorAll('.dm-conv-item').forEach(el => {
            el.addEventListener('click', () => this._openGroupChat(el.dataset.gid, el.dataset.gname));
        });
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
        this._updateGroupCallUI(groupId); // 通話中バナー・通話ボタンの状態更新
        if (this.el.groupInput) this.el.groupInput.focus();
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
            } else {
                this.el.groupBadge.style.display = 'none';
                this.el.groupBadge.textContent = '';
            }
        }
    }

    // =====================================================
    // メッシュ通話（複数人通話）
    // =====================================================

    /**
     * メッシュ通話用のpeer ID生成は廃止。
     * LinkUpの既存方式（サーバー側でpeer IDを自動生成し、Firebase経由でIDを交換する）
     * に合わせる。
     */

    _genMeshRoomId() {
        const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
        let s = '';
        for (let i = 0; i < 10; i++) s += chars[Math.floor(Math.random() * chars.length)];
        return s;
    }

    /**
     * グループタブからの「通話開始」ボタン押下時の処理
     * - メンバー全員に group_call_notify を送信し、自分はホストとしてメッシュ通話を開始する
     * - 着信モーダルは出さず、メンバーは通知バナーから任意で参加する
     */
    async _startGroupCall() {
        if (!this.currentGroupId) return;
        if (this.currentCall || this.callMode) {
            this.showNotification('通知', '現在通話中です', 'warning');
            return;
        }
        const group = this.myGroups.find(g => g.id === this.currentGroupId);
        if (!group) return;

        // 既にこのグループで通話が進行中なら、新規開始ではなく参加に切り替える
        if (this.activeGroupCalls.has(this.currentGroupId)) {
            return this._joinActiveGroupCall();
        }

        const roomId = `grp-${this.currentGroupId}-${Date.now().toString(36)}`;
        const groupName = group.name;
        const groupId = group.id;
        const myName = this.myName;

        // 自分をホストとして開始
        try {
            await this._enterMeshCall(roomId, true, { originGroupId: groupId });
        } catch (e) {
            this.showNotification('エラー', `通話の開始に失敗しました: ${e.message || e}`, 'error');
            return;
        }

        // 自分のactiveGroupCallsにも記録（一覧バッジ表示用）
        this.activeGroupCalls.set(groupId, {
            roomId,
            hostName: myName,
            hostPeerId: this.peer.id,
            participants: [myName],
            startedAt: Date.now(),
        });
        this._updateGroupCallUI(groupId);

        // グループメンバー全員に通知（自分以外）
        const payload = encodeURIComponent(JSON.stringify({
            groupId,
            groupName,
            roomId,
            hostName: myName,
            hostPeerId: this.peer.id,
        }));
        if (group.members) {
            for (const m of group.members) {
                if (m !== myName) {
                    FbAPI.sendSignal(this.token, m, 'group_call_notify', payload).catch(() => { });
                }
            }
        }
        // グループチャットにもシステムメッセージとして残す
        const sysMsg = { from: 'system', content: `📞 ${myName} がグループ通話を開始しました`, ts: Date.now(), type: 'system' };
        this._addMessage(this._groupKey(groupId), sysMsg);
        if (this.currentGroupId === groupId) this._renderGroupMessages(groupId);
    }

    /**
     * 「通話中バナー」からの参加ボタン押下時の処理
     */
    async _joinActiveGroupCall() {
        if (!this.currentGroupId) return;
        if (this.currentCall || this.callMode) {
            this.showNotification('通知', '現在通話中です', 'warning');
            return;
        }
        const info = this.activeGroupCalls.get(this.currentGroupId);
        if (!info) {
            this.showNotification('通知', '通話情報が見つかりません', 'warning');
            return;
        }
        try {
            await this._enterMeshCall(info.roomId, false, { originGroupId: this.currentGroupId, hostPeerId: info.hostPeerId });
        } catch (e) {
            this.showNotification('エラー', `通話への参加に失敗しました: ${e.message || e}`, 'error');
        }
    }

    /**
     * 受信: グループ通話開始通知
     */
    _receiveGroupCallNotify(fromName, gd) {
        if (!gd || !gd.groupId || !gd.roomId) return;
        // 自分がこのグループのメンバーか確認
        if (!this.myGroups.some(g => g.id === gd.groupId)) return;
        // ブロックチェック
        if (this.blockedUsers.has(fromName)) return;

        // 既に通話中で同じルームならスキップ
        if (this.meshRoomId === gd.roomId) return;

        // activeGroupCallsに記録
        this.activeGroupCalls.set(gd.groupId, {
            roomId: gd.roomId,
            hostName: gd.hostName || fromName,
            hostPeerId: gd.hostPeerId,
            participants: [gd.hostName || fromName],
            startedAt: Date.now(),
        });

        // システムメッセージとして履歴に残す
        const sysMsg = {
            from: 'system',
            content: `📞 ${gd.hostName || fromName} がグループ通話を開始しました`,
            ts: Date.now(),
            type: 'system',
        };
        this._addMessage(this._groupKey(gd.groupId), sysMsg);

        // 通知表示（軽め: 着信モーダルは出さない）
        this.showNotification('グループ通話', `${gd.hostName || fromName} がグループ通話を開始しました`, 'info');

        // 関連UIを更新
        this._updateGroupCallUI(gd.groupId);
        if (this.el.groupModal.classList.contains('visible') && !this.currentGroupId) {
            this._renderGroupList();
        }
    }

    /**
     * 受信: グループ通話終了通知
     */
    _receiveGroupCallEndNotify(gd) {
        if (!gd || !gd.groupId) return;
        const cur = this.activeGroupCalls.get(gd.groupId);
        if (!cur) return;
        if (gd.roomId && cur.roomId !== gd.roomId) return;
        this.activeGroupCalls.delete(gd.groupId);
        this._updateGroupCallUI(gd.groupId);
        if (this.el.groupModal.classList.contains('visible') && !this.currentGroupId) {
            this._renderGroupList();
        }
    }

    /**
     * グループチャット画面（開いている時）の通話バナー＆通話開始ボタンの状態を更新
     */
    _updateGroupCallUI(groupId) {
        // 別のグループを開いている場合は何もしない
        if (this.currentGroupId !== groupId) return;
        const info = this.activeGroupCalls.get(groupId);
        const banner = this.el.groupActiveCallBanner;
        const startBtn = this.el.groupCallStartBtn;
        if (!banner || !startBtn) return;

        // 自分が既にこのルームに参加しているかどうか
        const iAmInThisCall = this.callMode === 'mesh' && this.meshOriginGroupId === groupId;

        if (info && !iAmInThisCall) {
            // 通話中、自分は未参加 → バナー表示
            banner.style.display = '';
            const partCount = (info.participants?.length || 0) + this.meshPeers.size;
            if (this.el.groupActiveCallSub) {
                this.el.groupActiveCallSub.textContent = `参加中: ${info.participants?.length || 1}人`;
            }
            startBtn.style.display = 'none';
        } else if (iAmInThisCall) {
            // 自分が参加中
            banner.style.display = 'none';
            startBtn.style.display = '';
            startBtn.classList.add('active');
            startBtn.title = '通話中（クリックして通話画面へ）';
        } else {
            // 通話なし
            banner.style.display = 'none';
            startBtn.style.display = '';
            startBtn.classList.remove('active');
            startBtn.title = 'グループ通話を開始';
        }
    }

    /**
     * メッシュ通話のコア。
     * 既存の peer をいったん破棄してメッシュ専用peerを建てる。
     * 1対1からの昇格時もこの関数を通る（その場合 existingPeers でメンバー情報を引き継ぐ）。
     *
     * peer IDはサーバー側自動生成（LinkUpの既存方式と同じ）。
     * 参加者間でのpeer ID交換は、Firebase経由のシグナル + メッシュ確立後の
     * mesh-helloメッセージで行う。
     */
    async _enterMeshCall(roomId, isHost, opts = {}) {
        const { originGroupId = null, hostPeerId = null, existingPeers = null, existingStream = null } = opts;

        // ローカルストリームを準備
        if (!this.localStream) {
            await this.setupLocalStream();
        }

        // 旧 peer / call / dataConnection を破棄
        try { if (this.currentCall) this.currentCall.close(); } catch (_) { }
        try { if (this.dataConnection) this.dataConnection.close(); } catch (_) { }
        try { if (this.peer) this.peer.destroy(); } catch (_) { }
        this.currentCall = null;
        this.dataConnection = null;
        this.peer = null;

        // 新規メッシュpeerを生成（ID指定なし=サーバー側で自動生成）
        await new Promise((resolve, reject) => {
            const peer = new Peer({
                config: {
                    iceServers: [
                        { urls: 'stun:stun.l.google.com:19302' },
                        { urls: 'stun:stun1.google.com:19302' },
                    ],
                    iceTransportPolicy: 'all',
                    iceCandidatePoolSize: 10
                },
                secure: true,
                debug: 1,
            });

            const tm = setTimeout(() => {
                try { peer.destroy(); } catch (_) { }
                reject(new Error('シグナリングサーバーへの接続がタイムアウトしました'));
            }, 15000);

            peer.on('open', async id => {
                clearTimeout(tm);
                this.peer = peer;
                // heartbeatでもメッシュpeer.idを通知（オンラインリストとの整合性のため）
                if (this.token) {
                    try { await FbAPI.heartbeat(this.token, id); } catch (_) { }
                }
                resolve(id);
            });

            peer.on('error', err => {
                console.error('Mesh Peer error:', err);
                if (err.type === 'peer-unavailable') {
                    return; // 個別peerが消えただけ。再接続は試行しない
                }
                // 致命的エラー
                clearTimeout(tm);
                try { peer.destroy(); } catch (_) { }
                reject(err);
            });

            // 着信通話（他peerからのcall）
            peer.on('call', call => {
                call.answer(this.localStream || undefined);
                this._meshHandleIncomingCall(call);
            });

            // データ接続（他peerからのconn）
            peer.on('connection', conn => {
                this._meshSetupDataConnection(conn);
            });

            peer.on('disconnected', () => {
                setTimeout(() => {
                    if (this.peer === peer) {
                        try { this.peer.reconnect(); } catch (_) { }
                    }
                }, 3000);
            });
        });

        // state更新
        this.callMode = 'mesh';
        this.meshRoomId = roomId;
        this.meshIsHost = isHost;
        this.meshOriginGroupId = originGroupId;
        this.meshHostPeerId = isHost ? this.peer.id : hostPeerId; // 非ホストは引数で受け取ったhostPeerIdを保持
        this.meshPeers = new Map();

        // UI切替: 1対1のvideoGridを隠してmeshGridを表示
        this.el.videoGrid.style.display = 'none';
        if (this.el.meshGrid) this.el.meshGrid.style.display = '';
        this.el.waitingState.style.display = 'none';
        this.el.callControls.style.display = '';
        if (this.el.meshInviteBtn) this.el.meshInviteBtn.style.display = '';
        if (this.el.meshMicBtn) this.el.meshMicBtn.style.display = '';
        if (this.el.meshCamBtn) this.el.meshCamBtn.style.display = '';
        // 1対1用の音量スライダーは不要
        if (this.el.volumeSliderContainer) this.el.volumeSliderContainer.classList.remove('visible');
        this.showUserListSection(false);

        // 自分のタイルを作成
        this._meshEnsureTile(this.peer.id, true, this.myName, this.myAvatar);
        this._meshSetTileStream(this.peer.id, this.localStream);
        this._meshSetTileStatus(this.peer.id, this.isAudioEnabled, this.isVideoEnabled);
        this._updateMeshControlButtons();

        this.updateStatus('グループ通話中');

        // ホストでなければ、ホストに接続を試みる
        if (!isHost && this.meshHostPeerId) {
            setTimeout(() => this._meshConnectToPeer(this.meshHostPeerId), 500);
        }

        // 自分も activeGroupCalls に参加者として記録（グループ通話の場合）
        if (originGroupId) {
            let info = this.activeGroupCalls.get(originGroupId);
            if (!info) {
                info = { roomId, hostName: isHost ? this.myName : null, hostPeerId: this.meshHostPeerId, participants: [], startedAt: Date.now() };
                this.activeGroupCalls.set(originGroupId, info);
            }
            if (!info.participants.includes(this.myName)) {
                info.participants.push(this.myName);
            }
            this._updateGroupCallUI(originGroupId);
        }
    }

    /**
     * メッシュ通話の他peerに接続する（自分から call + connect する側）
     */
    _meshConnectToPeer(remotePeerId) {
        if (!this.peer) return;
        if (remotePeerId === this.peer.id) return;
        if (this.meshPeers.has(remotePeerId) && this.meshPeers.get(remotePeerId).conn) return;

        // 人数上限チェック
        if (this.meshPeers.size + 1 >= this.MESH_MAX_PARTICIPANTS) {
            console.warn('[mesh] 最大人数に達しているため接続を試みません', remotePeerId);
            return;
        }

        const conn = this.peer.connect(remotePeerId, { reliable: true });
        this._meshSetupDataConnection(conn);

        const call = this.peer.call(remotePeerId, this.localStream || undefined);
        if (call) {
            let info = this.meshPeers.get(remotePeerId);
            if (!info) {
                info = { call: null, conn: null, name: '...', stream: null, micOn: true, camOn: true, avatar: null };
                this.meshPeers.set(remotePeerId, info);
            }
            info.call = call;
            this._meshEnsureTile(remotePeerId, false, info.name, info.avatar);

            call.on('stream', stream => {
                info.stream = stream;
                this._meshSetTileStream(remotePeerId, stream);
            });
            call.on('close', () => this._meshCleanupPeer(remotePeerId));
            call.on('error', err => console.error('Mesh Call error:', err));
        }
    }

    _meshHandleIncomingCall(call) {
        const remoteId = call.peer;
        let info = this.meshPeers.get(remoteId);
        if (!info) {
            info = { call: null, conn: null, name: '...', stream: null, micOn: true, camOn: true, avatar: null };
            this.meshPeers.set(remoteId, info);
        }
        info.call = call;
        this._meshEnsureTile(remoteId, false, info.name, info.avatar);

        call.on('stream', stream => {
            info.stream = stream;
            this._meshSetTileStream(remoteId, stream);
        });
        call.on('close', () => this._meshCleanupPeer(remoteId));
        call.on('error', err => console.error('Mesh Call error:', err));
    }

    _meshSetupDataConnection(conn) {
        const remoteId = conn.peer;
        let info = this.meshPeers.get(remoteId);
        if (!info) {
            info = { call: null, conn: null, name: '...', stream: null, micOn: true, camOn: true, avatar: null };
            this.meshPeers.set(remoteId, info);
        }
        info.conn = conn;

        conn.on('open', () => {
            // 自己紹介を送信
            try {
                conn.send({
                    type: 'mesh-hello',
                    name: this.myName,
                    avatar: this.myAvatar || null,
                    micOn: this.isAudioEnabled,
                    camOn: this.isVideoEnabled,
                });
                // ホストの場合は参加者リストを返信
                if (this.meshIsHost) {
                    const peerList = [...this.meshPeers.keys()].filter(id => id !== remoteId);
                    conn.send({ type: 'mesh-peer-list', peers: peerList });
                }
            } catch (_) { }
        });

        conn.on('data', data => this._meshHandleData(remoteId, data));
        conn.on('close', () => this._meshCleanupPeer(remoteId));
    }

    _meshHandleData(remoteId, data) {
        const info = this.meshPeers.get(remoteId);
        if (!info) return;

        if (data.type === 'mesh-hello') {
            info.name = data.name || '匿名';
            info.avatar = data.avatar || null;
            info.micOn = data.micOn !== false;
            info.camOn = data.camOn !== false;
            this._meshEnsureTile(remoteId, false, info.name, info.avatar);
            this._meshSetTileName(remoteId, info.name);
            this._meshSetTileAvatar(remoteId, info.avatar);
            this._meshSetTileStatus(remoteId, info.micOn, info.camOn);
            // アバターキャッシュにも反映
            if (info.avatar && info.name) {
                this.avatarCache[info.name] = info.avatar;
            }
            // グループ通話の参加者リストにも反映
            if (this.meshOriginGroupId) {
                const ginfo = this.activeGroupCalls.get(this.meshOriginGroupId);
                if (ginfo && !ginfo.participants.includes(info.name)) {
                    ginfo.participants.push(info.name);
                    this._updateGroupCallUI(this.meshOriginGroupId);
                }
            }
        }
        else if (data.type === 'mesh-peer-list') {
            // ホストから他参加者のpeer_idリストを受け取った
            (data.peers || []).forEach(pid => {
                if (pid !== this.peer.id && !this.meshPeers.has(pid)) {
                    this._meshConnectToPeer(pid);
                }
            });
        }
        else if (data.type === 'mesh-state') {
            info.micOn = data.micOn;
            info.camOn = data.camOn;
            this._meshSetTileStatus(remoteId, info.micOn, info.camOn);
        }
        else if (data.type === 'mesh-bye') {
            this._meshCleanupPeer(remoteId);
        }
    }

    _meshCleanupPeer(peerId) {
        const info = this.meshPeers.get(peerId);
        if (info) {
            if (info.call) { try { info.call.close(); } catch (_) { } }
            if (info.conn) { try { info.conn.close(); } catch (_) { } }
            this.meshPeers.delete(peerId);
            // グループ通話の参加者リストからも除外
            if (this.meshOriginGroupId && info.name && info.name !== '...') {
                const ginfo = this.activeGroupCalls.get(this.meshOriginGroupId);
                if (ginfo) {
                    ginfo.participants = ginfo.participants.filter(n => n !== info.name);
                    this._updateGroupCallUI(this.meshOriginGroupId);
                }
            }
        }
        this._meshRemoveTile(peerId);
    }

    _meshBroadcastState() {
        const msg = { type: 'mesh-state', micOn: this.isAudioEnabled, camOn: this.isVideoEnabled };
        this.meshPeers.forEach(info => {
            if (info.conn && info.conn.open) {
                try { info.conn.send(msg); } catch (_) { }
            }
        });
    }

    // ===== メッシュ通話タイル UI =====
    _meshEnsureTile(peerId, isSelf, name, avatar) {
        if (!this.el.meshGrid) return;
        let tile = this.el.meshGrid.querySelector(`[data-mesh-tile="${CSS.escape(peerId)}"]`);
        if (tile) return tile;

        tile = document.createElement('div');
        tile.className = 'mesh-tile' + (isSelf ? ' self' : '');
        tile.dataset.meshTile = peerId;
        const displayName = this.escapeHtml(name || '...');
        const initial = this.escapeHtml((name || '?').charAt(0).toUpperCase());
        const noVideoStyle = avatar ? `background-image:url('${avatar}')` : '';
        const noVideoClass = avatar ? 'mesh-tile-no-video has-avatar' : 'mesh-tile-no-video';
        tile.innerHTML = `
            <video autoplay playsinline ${isSelf ? 'muted' : ''}${isSelf ? ' class="mirror"' : ''}></video>
            <div class="${noVideoClass}" style="${noVideoStyle};display:none">${avatar ? '' : initial}</div>
            <div class="mesh-tile-label"><span class="mesh-tile-name">${displayName}</span>${isSelf ? ' <span style="opacity:0.7">(あなた)</span>' : ''}</div>
            <div class="mesh-tile-status"></div>
        `;
        this.el.meshGrid.appendChild(tile);
        this._meshUpdateGridCount();
        return tile;
    }

    _meshRemoveTile(peerId) {
        if (!this.el.meshGrid) return;
        const tile = this.el.meshGrid.querySelector(`[data-mesh-tile="${CSS.escape(peerId)}"]`);
        if (tile) tile.remove();
        this._meshUpdateGridCount();
    }

    _meshUpdateGridCount() {
        if (!this.el.meshGrid) return;
        const n = this.el.meshGrid.children.length;
        this.el.meshGrid.dataset.count = n;
    }

    _meshSetTileStream(peerId, stream) {
        if (!this.el.meshGrid) return;
        const tile = this.el.meshGrid.querySelector(`[data-mesh-tile="${CSS.escape(peerId)}"]`);
        if (!tile) return;
        const video = tile.querySelector('video');
        if (video && video.srcObject !== stream) {
            video.srcObject = stream;
        }
        // ストリームのトラック状態に応じて表示を更新
        if (stream) {
            const videoTrack = stream.getVideoTracks()[0];
            const audioTrack = stream.getAudioTracks()[0];
            const camOn = videoTrack && videoTrack.enabled && !videoTrack.muted;
            const micOn = audioTrack && audioTrack.enabled && !audioTrack.muted;
            this._meshSetTileStatus(peerId, micOn !== false, camOn !== false);
        }
    }

    _meshSetTileName(peerId, name) {
        if (!this.el.meshGrid) return;
        const tile = this.el.meshGrid.querySelector(`[data-mesh-tile="${CSS.escape(peerId)}"]`);
        if (!tile) return;
        const nameEl = tile.querySelector('.mesh-tile-name');
        if (nameEl) nameEl.textContent = name;
        const overlay = tile.querySelector('.mesh-tile-no-video');
        if (overlay && !overlay.classList.contains('has-avatar')) {
            overlay.textContent = (name || '?').charAt(0).toUpperCase();
        }
    }

    _meshSetTileAvatar(peerId, avatar) {
        if (!this.el.meshGrid) return;
        const tile = this.el.meshGrid.querySelector(`[data-mesh-tile="${CSS.escape(peerId)}"]`);
        if (!tile) return;
        const overlay = tile.querySelector('.mesh-tile-no-video');
        if (overlay) {
            if (avatar) {
                overlay.style.backgroundImage = `url('${avatar}')`;
                overlay.classList.add('has-avatar');
                overlay.textContent = '';
            } else {
                overlay.style.backgroundImage = '';
                overlay.classList.remove('has-avatar');
            }
        }
    }

    _meshSetTileStatus(peerId, micOn, camOn) {
        if (!this.el.meshGrid) return;
        const tile = this.el.meshGrid.querySelector(`[data-mesh-tile="${CSS.escape(peerId)}"]`);
        if (!tile) return;
        const statusEl = tile.querySelector('.mesh-tile-status');
        if (statusEl) {
            statusEl.innerHTML = '';
            if (!micOn) {
                statusEl.innerHTML += `<div class="mesh-status-icon muted" title="ミュート"><i class="fas fa-microphone-slash"></i></div>`;
            }
            if (!camOn) {
                statusEl.innerHTML += `<div class="mesh-status-icon cam-off" title="カメラOFF"><i class="fas fa-video-slash"></i></div>`;
            }
        }
        // カメラオフ時はno-videoオーバーレイ表示
        const overlay = tile.querySelector('.mesh-tile-no-video');
        const video = tile.querySelector('video');
        if (overlay && video) {
            if (!camOn) {
                overlay.style.display = 'flex';
                video.style.opacity = '0';
            } else {
                overlay.style.display = 'none';
                video.style.opacity = '1';
            }
        }
    }

    // ===== メッシュ通話: コントロール =====
    _toggleMeshMic() {
        if (!this.peer) return;
        this.isAudioEnabled = !this.isAudioEnabled;
        if (this.localStream) {
            this.localStream.getAudioTracks().forEach(t => t.enabled = this.isAudioEnabled);
        }
        this._meshSetTileStatus(this.peer.id, this.isAudioEnabled, this.isVideoEnabled);
        this._updateMeshControlButtons();
        this._meshBroadcastState();
    }

    _toggleMeshCam() {
        if (!this.peer) return;
        this.isVideoEnabled = !this.isVideoEnabled;
        if (this.localStream) {
            this.localStream.getVideoTracks().forEach(t => t.enabled = this.isVideoEnabled);
        }
        this._meshSetTileStatus(this.peer.id, this.isAudioEnabled, this.isVideoEnabled);
        this._updateMeshControlButtons();
        this._meshBroadcastState();
    }

    _updateMeshControlButtons() {
        if (this.el.meshMicBtn) {
            this.el.meshMicBtn.classList.toggle('off', !this.isAudioEnabled);
            this.el.meshMicBtn.innerHTML = this.isAudioEnabled
                ? '<i class="fas fa-microphone"></i>'
                : '<i class="fas fa-microphone-slash"></i>';
        }
        if (this.el.meshCamBtn) {
            this.el.meshCamBtn.classList.toggle('off', !this.isVideoEnabled);
            this.el.meshCamBtn.innerHTML = this.isVideoEnabled
                ? '<i class="fas fa-video"></i>'
                : '<i class="fas fa-video-slash"></i>';
        }
    }

    /**
     * メッシュ通話から退出する
     */
    async _leaveMeshCall(opts = {}) {
        const { silent = false } = opts;
        if (this.callMode !== 'mesh') return;
        if (!silent) {
            if (!confirm('通話から退出しますか？')) return;
        }

        // 全peerに bye 送信
        this.meshPeers.forEach(info => {
            if (info.conn && info.conn.open) {
                try { info.conn.send({ type: 'mesh-bye' }); } catch (_) { }
            }
        });

        // ホストが退出する＆これが最後の参加者なら、グループに終了通知を出す
        const wasHost = this.meshIsHost;
        const originGroup = this.meshOriginGroupId;
        const wasLastInRoom = this.meshPeers.size === 0;

        // ストリームは保持（次回通話で再利用）
        // peer は破棄
        try { if (this.peer) this.peer.destroy(); } catch (_) { }
        this.peer = null;
        this.meshPeers.clear();

        // UI戻し
        if (this.el.meshGrid) {
            this.el.meshGrid.innerHTML = '';
            this.el.meshGrid.dataset.count = '0';
            this.el.meshGrid.style.display = 'none';
        }
        this.el.videoGrid.style.display = 'none';
        this.el.waitingState.style.display = '';
        this.el.callControls.style.display = 'none';
        if (this.el.meshInviteBtn) this.el.meshInviteBtn.style.display = 'none';
        if (this.el.meshMicBtn) this.el.meshMicBtn.style.display = 'none';
        if (this.el.meshCamBtn) this.el.meshCamBtn.style.display = 'none';
        this.showUserListSection(true);

        // activeGroupCalls から自分を除外
        if (originGroup) {
            const info = this.activeGroupCalls.get(originGroup);
            if (info) {
                info.participants = info.participants.filter(n => n !== this.myName);
                // 自分が最後の参加者かつホストの場合は通話終了とみなす
                if (wasHost && wasLastInRoom) {
                    this.activeGroupCalls.delete(originGroup);
                    // グループメンバー全員に終了通知
                    const group = this.myGroups.find(g => g.id === originGroup);
                    if (group?.members) {
                        const payload = encodeURIComponent(JSON.stringify({ groupId: originGroup, roomId: this.meshRoomId }));
                        for (const m of group.members) {
                            if (m !== this.myName) {
                                FbAPI.sendSignal(this.token, m, 'group_call_end_notify', payload).catch(() => { });
                            }
                        }
                    }
                }
                this._updateGroupCallUI(originGroup);
            }
        }

        // メッシュ通話のstateリセット
        this.callMode = null;
        this.meshRoomId = null;
        this.meshIsHost = false;
        this.meshOriginGroupId = null;
        this.meshHostPeerId = null;

        // 通常の1対1用peerを再初期化（既存の通話受信フローを復活）
        try {
            await this.initializePeer();
            if (this.el.localVideo && this.localStream) {
                if (this.el.localVideo.srcObject !== this.localStream) {
                    this.el.localVideo.srcObject = this.localStream;
                }
                this.el.localVideo.style.display = '';
            }
        } catch (e) {
            console.warn('mesh退出後の再初期化失敗:', e);
        }

        this.updateStatus('オンライン');
        await this.refreshOnlineList();
    }

    // ===== 1対1 → メッシュへの昇格 =====

    /**
     * 通話中の「招待」ボタン押下時に、招待候補リストを表示する
     * 候補: 自分のフレンド ∪ 通話中の他参加者のフレンド（重複除く）から、
     *       現在の通話参加者を除く、オンラインのユーザー。
     */
    async _openMeshInviteSelectModal() {
        if (!this.callMode) return;
        // 最大人数チェック（自分 + meshPeers）
        const currentCount = (this.callMode === 'mesh') ? (1 + this.meshPeers.size) : 2;
        const remainSlots = this.MESH_MAX_PARTICIPANTS - currentCount;
        if (this.el.meshInviteSlotInfo) {
            this.el.meshInviteSlotInfo.textContent = `現在 ${currentCount} 人 / 最大 ${this.MESH_MAX_PARTICIPANTS} 人（あと ${Math.max(0, remainSlots)} 人招待可能）`;
        }
        if (remainSlots <= 0) {
            this.el.meshInviteCandidateList.innerHTML = `<div class="friend-empty"><i class="fas fa-users"></i><p>これ以上招待できません（最大人数）</p></div>`;
            this.el.meshInviteSelectModal.classList.add('visible');
            return;
        }

        // 通話中の参加者名集合（自分含む）
        const participantNames = new Set();
        participantNames.add(this.myName);
        if (this.callMode === 'mesh') {
            this.meshPeers.forEach(p => { if (p.name && p.name !== '...') participantNames.add(p.name); });
        } else if (this.callMode === 'one-to-one' && this.callTargetName) {
            participantNames.add(this.callTargetName);
        }

        // 招待可能な候補フレンド名（自分のフレンド + 既知の参加者フレンド）
        // 1対1モードで相手のフレンドリストを別途取得する仕組みは現状ないので、
        // ひとまず「自分のフレンド」のみを候補とする。
        // ※ メッシュ移行後、参加者間でフレンド情報を交換する設計の余地は残す。
        const candidateNames = new Set(this.friendNames);
        participantNames.forEach(n => candidateNames.delete(n));

        // オンラインリストの最新を取得（peer_idも必要）
        let users = this._lastOnlineUsers || [];
        try {
            const res = await FbAPI.onlineList(this.token);
            if (res?.ok) {
                this._lastOnlineUsers = res.users || [];
                users = res.users || [];
            }
        } catch (_) { }

        const onlineCandidates = users.filter(u => candidateNames.has(u.name));
        // フレンドだけどオフラインの人も「(オフライン)」として薄く表示する
        const offlineCandidates = [...candidateNames]
            .filter(n => !users.some(u => u.name === n))
            .map(n => ({ name: n, peer_id: '' }));

        const html = [...onlineCandidates, ...offlineCandidates].map(u => {
            const isOnline = !!u.peer_id;
            const avatar = this.avatarCache[u.name];
            const avStyle = avatar ? `background-image:url('${avatar}')` : '';
            const initial = avatar ? '' : this.escapeHtml(u.name.charAt(0).toUpperCase());
            return `
                <div class="mesh-invite-candidate ${isOnline ? '' : 'disabled'}" data-name="${this.escapeHtml(u.name)}" data-peer="${this.escapeHtml(u.peer_id)}">
                    <div class="mesh-invite-candidate-avatar" style="${avStyle}">${initial}</div>
                    <div class="mesh-invite-candidate-info">
                        <span class="mesh-invite-candidate-name">${this.escapeHtml(u.name)}</span>
                        <span class="mesh-invite-candidate-sub">${isOnline ? 'オンライン' : 'オフライン'}</span>
                    </div>
                    <button class="mesh-invite-candidate-send" ${isOnline ? '' : 'disabled'}>
                        <i class="fas fa-paper-plane"></i> 招待
                    </button>
                </div>
            `;
        }).join('') || '<div class="friend-empty"><i class="fas fa-user-slash"></i><p>招待できるフレンドがいません</p></div>';

        this.el.meshInviteCandidateList.innerHTML = html;

        // クリックハンドラ
        this.el.meshInviteCandidateList.querySelectorAll('.mesh-invite-candidate-send').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const item = btn.closest('.mesh-invite-candidate');
                const name = item?.dataset.name;
                if (name) this._sendMeshInvite(name);
            });
        });
        this.el.meshInviteCandidateList.querySelectorAll('.mesh-invite-candidate').forEach(el => {
            if (!el.classList.contains('disabled')) {
                el.addEventListener('click', () => {
                    const name = el.dataset.name;
                    if (name) this._sendMeshInvite(name);
                });
            }
        });

        this.el.meshInviteSelectModal.classList.add('visible');
    }

    /**
     * メッシュ通話の招待を送信する
     * - 1対1モード中なら、まず自分自身と既存の1対1相手にメッシュ昇格を促す
     * - メッシュモード中なら、新規参加者に招待を送るだけ
     */
    async _sendMeshInvite(targetName) {
        if (!targetName) return;
        if (this.blockedUsers.has(targetName)) {
            this.showNotification('通知', `${targetName} はブロック中のため招待できません`, 'warning');
            return;
        }

        // 1対1モードなら、メッシュへの昇格処理が必要
        let roomId, hostPeerId, hostName, originGroupId;
        let wasOneToOne = false;
        if (this.callMode === 'one-to-one') {
            wasOneToOne = true;
            // 新しいルームIDを生成、自分がホストになる
            roomId = `inv-${this._genMeshRoomId()}`;
            hostName = this.myName;
            originGroupId = null;
            const prevPartnerName = this.callTargetName;
            // 「これからメッシュに昇格する」と相手にdataConnection経由で通知
            // → 相手側でclose時に「通話終了しました」と表示されるのを防ぐ
            this._upgradingToMesh = true;
            if (this.dataConnection && this.dataConnection.open) {
                try { this.dataConnection.send({ type: 'UPGRADE_TO_MESH' }); } catch (_) { }
                await new Promise(r => setTimeout(r, 150)); // 送信完了待ち
            }
            // 自分が先にメッシュ通話モードへ移行（ホスト）
            try {
                await this._enterMeshCall(roomId, true, { originGroupId: null });
            } catch (e) {
                this._upgradingToMesh = false;
                this.showNotification('エラー', `メッシュ通話への移行に失敗しました: ${e.message || e}`, 'error');
                return;
            }
            this._upgradingToMesh = false;
            hostPeerId = this.peer.id;
            // 既存相手に「メッシュ昇格招待」シグナルを送る（自分の新しいpeer.idを知らせる）
            const payloadForPartner = encodeURIComponent(JSON.stringify({
                roomId,
                hostName: this.myName,
                hostPeerId,
                participants: [this.myName, prevPartnerName, targetName],
                upgradeFromOneToOne: true,
                inviterName: this.myName,
            }));
            try {
                await FbAPI.sendSignal(this.token, prevPartnerName, 'mesh_invite', payloadForPartner);
            } catch (_) { }
        } else if (this.callMode === 'mesh') {
            roomId = this.meshRoomId;
            hostPeerId = this.meshHostPeerId;
            hostName = this.meshIsHost ? this.myName : null;
            originGroupId = this.meshOriginGroupId;
        } else {
            return;
        }

        // 新規招待先に招待シグナル送信
        const currentParticipants = [this.myName];
        this.meshPeers.forEach(p => { if (p.name && p.name !== '...') currentParticipants.push(p.name); });
        const payload = encodeURIComponent(JSON.stringify({
            roomId,
            hostName: hostName || this.myName,
            hostPeerId,
            participants: currentParticipants,
            inviterName: this.myName,
            originGroupId,
        }));
        try {
            const res = await FbAPI.sendSignal(this.token, targetName, 'mesh_invite', payload);
            if (res?.ok) {
                this.showNotification('招待', `${targetName} に通話招待を送りました`, 'success');
            } else {
                this.showNotification('エラー', `招待の送信に失敗しました: ${res?.error || ''}`, 'error');
            }
        } catch (_) {
            this.showNotification('エラー', '招待の送信に失敗しました', 'error');
        }

        if (this.el.meshInviteSelectModal) {
            this.el.meshInviteSelectModal.classList.remove('visible');
        }
    }

    /**
     * 受信: メッシュ通話への招待
     * - 1対1中に来た「昇格招待」と、グループ通話とは別個の純粋なメッシュ招待の両方を扱う
     */
    _showMeshInvite(fromName, inv) {
        if (this.pendingMeshInvite) return; // 既に保留中
        if (!inv || !inv.roomId) return;

        // 既にこのroomに居る場合は無視
        if (this.meshRoomId === inv.roomId) return;

        // 1対1中で、自分がこの招待の対象（昇格招待）の場合
        // → 既存の1対1接続を一旦終了し、メッシュへ移行する
        if (inv.upgradeFromOneToOne && this.callMode === 'one-to-one'
            && this.callTargetName === fromName) {
            // 自動的にメッシュへ昇格（モーダル無し、シームレス）
            this._upgradingToMesh = true;
            (async () => {
                try {
                    await this._enterMeshCall(inv.roomId, false, {
                        originGroupId: null,
                        hostPeerId: inv.hostPeerId,
                    });
                    this.showNotification('通話', `グループ通話に切り替わりました`, 'info');
                } catch (e) {
                    this.showNotification('エラー', `メッシュ通話への移行に失敗しました: ${e.message || e}`, 'error');
                } finally {
                    this._upgradingToMesh = false;
                }
            })();
            return;
        }

        // それ以外（新規メッシュ招待） → モーダルを表示
        this.pendingMeshInvite = { from: fromName, ...inv };
        if (this.el.meshInviteFrom) this.el.meshInviteFrom.textContent = fromName;
        if (this.el.meshInviteMembers) {
            const others = (inv.participants || []).filter(n => n !== fromName);
            const text = others.length > 0
                ? `参加中: ${fromName}, ${others.join(', ')}`
                : `参加中: ${fromName}`;
            this.el.meshInviteMembers.textContent = text;
        }
        this.el.meshInviteModal.classList.add('visible');

        // 30秒タイムアウト
        clearTimeout(this._meshInviteTimeout);
        this._meshInviteTimeout = setTimeout(() => {
            if (this.el.meshInviteModal.classList.contains('visible')) {
                this._handleMeshInvite(false);
            }
        }, 30000);
    }

    async _handleMeshInvite(accept) {
        clearTimeout(this._meshInviteTimeout);
        const inv = this.pendingMeshInvite;
        this.pendingMeshInvite = null;
        this.el.meshInviteModal.classList.remove('visible');

        if (!inv) return;

        if (!accept) {
            // 拒否通知を送信
            try {
                await FbAPI.sendSignal(this.token, inv.from, 'mesh_invite_reject', '');
            } catch (_) { }
            return;
        }

        // 既に通話中なら確認
        if (this.callMode) {
            if (!confirm('現在の通話を終了して、新しい通話に参加しますか？')) return;
            if (this.callMode === 'mesh') {
                await this._leaveMeshCall({ silent: true });
            } else if (this.callMode === 'one-to-one') {
                await this.disconnect();
                // disconnect後は少し待つ
                await new Promise(r => setTimeout(r, 300));
            }
        }

        // メッシュ通話に参加
        try {
            await this._enterMeshCall(inv.roomId, false, {
                originGroupId: inv.originGroupId || null,
                hostPeerId: inv.hostPeerId,
            });
        } catch (e) {
            this.showNotification('エラー', `通話への参加に失敗しました: ${e.message || e}`, 'error');
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
        if (msg.type === 'file' && msg.file) {
            const f = msg.file;
            if (f.type?.startsWith('image/')) {
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
        // 自分が送ったメッセージにだけ既読表示
        let readReceiptHtml = '';
        if (isMine && ctx) {
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
        return `<div class="chat-msg ${isMine ? 'mine' : 'theirs'}"${msgIdAttr}>
            ${avatarHtml}
            <div class="chat-msg-body">
                ${!isMine ? `<div class="chat-msg-name">${this.escapeHtml(msg.from || '')}</div>` : ''}
                <div class="chat-msg-bubble">${contentHtml}</div>
                <div class="chat-msg-time">${time}</div>
                ${readReceiptHtml}
            </div>
        </div>`;
    }

    // =====================================================
    // 音声・映像制御
    // =====================================================
    toggleAudio() {
        this.isAudioEnabled = !this.isAudioEnabled;
        if (this.localStream) this.localStream.getAudioTracks().forEach(t => t.enabled = this.isAudioEnabled);
        this.el.toggleMicButton.classList.toggle('active', !this.isAudioEnabled);
        this.el.toggleMicButton.querySelector('i').className = this.isAudioEnabled ? 'fas fa-microphone' : 'fas fa-microphone-slash';
    }

    toggleVideo() {
        this.isVideoEnabled = !this.isVideoEnabled;
        if (this.localStream) this.localStream.getVideoTracks().forEach(t => t.enabled = this.isVideoEnabled);
        this.el.toggleVideoButton.classList.toggle('active', !this.isVideoEnabled);
        this.el.toggleVideoButton.querySelector('i').className = this.isVideoEnabled ? 'fas fa-video' : 'fas fa-video-slash';
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
        // メッシュ通話中の場合: 全peerに bye 送信
        if (this.meshPeers && this.meshPeers.size > 0) {
            this.meshPeers.forEach(info => {
                if (info.conn && info.conn.open) {
                    try { info.conn.send({ type: 'mesh-bye' }); } catch (_) { }
                }
            });
        }
        // メッシュ通話のホストかつ最後の参加者なら、グループに終了通知
        if (this.callMode === 'mesh' && this.meshIsHost && this.meshPeers.size === 0 && this.meshOriginGroupId) {
            const group = this.myGroups.find(g => g.id === this.meshOriginGroupId);
            if (group?.members && this.token) {
                const payload = encodeURIComponent(JSON.stringify({ groupId: this.meshOriginGroupId, roomId: this.meshRoomId }));
                for (const m of group.members) {
                    if (m !== this.myName) {
                        try { FbAPI.sendSignal(this.token, m, 'group_call_end_notify', payload); } catch (_) { }
                    }
                }
            }
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
        this.cleanup();
    }
}

// =====================================================
// エントリポイント
// =====================================================
window.addEventListener('DOMContentLoaded', () => {
    new SecureVideoChat();
});