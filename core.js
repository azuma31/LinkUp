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

