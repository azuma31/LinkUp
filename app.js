// 暗号化ユーティリティクラス
class CryptoUtil {
    static async generateKey() {
        return await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
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
        const keyBytes = new Uint8Array(keyData.match(/.{2}/g)
            .map(byte => parseInt(byte, 16)));
        return await window.crypto.subtle.importKey(
            "raw",
            keyBytes,
            "AES-GCM",
            true,
            ["encrypt", "decrypt"]
        );
    }

    static async encrypt(key, data) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            data
        );
        return {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted))
        };
    }

    static async decrypt(key, iv, encryptedData) {
        return await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: new Uint8Array(iv)
            },
            key,
            new Uint8Array(encryptedData)
        );
    }
}

// メインアプリケーションクラス
class SecureVideoChat {
    constructor() {
        this.peer = null;
        this.currentCall = null;
        this.encryptionKey = null;
        this.dataConnection = null;
        this.localStream = null;
        this.isAudioEnabled = true;
        this.isVideoEnabled = true;

        this.initializeElements();
        this.initializePeer();
        this.setupEventListeners();
        this.setupCopyButtons();
    }

    // DOM要素の初期化
    initializeElements() {
        this.elements = {
            localVideo: document.getElementById('localVideo'),
            remoteVideo: document.getElementById('remoteVideo'),
            connectButton: document.getElementById('connectButton'),
            disconnectButton: document.getElementById('disconnectButton'),
            remotePeerId: document.getElementById('remotePeerId'),
            localPeerId: document.getElementById('localPeerId'),
            encryptionKeyDisplay: document.getElementById('encryptionKey'),
            connectionStatus: document.getElementById('connectionStatus'),
            connectionQuality: document.getElementById('connectionQuality'),
            toggleMicButton: document.getElementById('toggleMicButton'),
            toggleVideoButton: document.getElementById('toggleVideoButton'),
            statusIndicator: document.querySelector('.status-indicator')
        };
    }

    // PeerJSの初期化
    async initializePeer() {
        try {
            // 暗号化キーの生成
            this.encryptionKey = await CryptoUtil.generateKey();
            const exportedKey = await CryptoUtil.exportKey(this.encryptionKey);
            this.elements.encryptionKeyDisplay.value = exportedKey;

            // PeerJSの設定
            this.peer = new Peer({
                config: {
                    iceServers: [
                        { urls: 'stun:stun.l.google.com:19302' },
                        { urls: 'stun:stun1.l.google.com:19302' },
                        { urls: 'stun:stun2.l.google.com:19302' },
                        {
                            urls: 'turn:numb.viagenie.ca',
                            username: 'webrtc@live.com',
                            credential: 'muazkh'
                        }
                    ],
                    iceTransportPolicy: 'all',
                    iceCandidatePoolSize: 10
                },
                secure: true,
                debug: 3
            });

            this.setupPeerEventListeners();
            await this.setupLocalStream();
        } catch (error) {
            this.showNotification('エラー', `初期化に失敗しました: ${error.message}`, 'error');
        }
    }

    // PeerJSのイベントリスナー設定
    setupPeerEventListeners() {
        this.peer.on('open', id => {
            this.elements.localPeerId.value = id;
            this.updateStatus('準備完了');
        });

        this.peer.on('call', async call => {
            try {
                call.answer(this.localStream);
                this.handleCall(call);
                this.updateStatus('通話中');
            } catch (error) {
                this.showNotification('エラー', '着信応答に失敗しました', 'error');
            }
        });

        this.peer.on('connection', conn => {
            this.dataConnection = conn;
            this.setupDataConnection();
        });

        this.peer.on('error', error => {
            this.showNotification('エラー', `接続エラー: ${error.message}`, 'error');
            this.updateStatus('エラー発生', true);
        });

        this.peer.on('disconnected', () => {
            this.updateStatus('切断されました', true);
            setTimeout(() => {
                if (this.peer) {
                    this.peer.reconnect();
                }
            }, 3000);
        });
    }

    // ローカルストリームのセットアップ
    async setupLocalStream() {
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: true
            });
            this.elements.localVideo.srcObject = this.localStream;
            this.updateStatus('カメラ準備完了');
        } catch (error) {
            this.showNotification('エラー', 'カメラ/マイクの取得に失敗しました', 'error');
            this.updateStatus('メディア取得エラー', true);
        }
    }

    // イベントリスナーの設定
    setupEventListeners() {
        this.elements.connectButton.addEventListener('click', () => this.connect());
        this.elements.disconnectButton.addEventListener('click', () => this.disconnect());
        this.elements.toggleMicButton.addEventListener('click', () => this.toggleAudio());
        this.elements.toggleVideoButton.addEventListener('click', () => this.toggleVideo());
    }

    // コピーボタンの設定
    setupCopyButtons() {
        document.querySelectorAll('.copy-btn').forEach(button => {
            button.addEventListener('click', () => {
                const targetId = button.dataset.target;
                const input = document.getElementById(targetId);
                input.select();
                document.execCommand('copy');
                this.showNotification('成功', 'コピーしました', 'success');
            });
        });
    }

    // 接続処理
    async connect() {
        const remotePeerId = this.elements.remotePeerId.value;
        if (!remotePeerId) {
            this.showNotification('警告', '相手のIDを入力してください', 'warning');
            return;
        }

        try {
            this.updateStatus('接続中...');
            this.dataConnection = this.peer.connect(remotePeerId);
            this.setupDataConnection();

            const call = this.peer.call(remotePeerId, this.localStream);
            this.handleCall(call);

            this.elements.connectButton.disabled = true;
            this.elements.disconnectButton.disabled = false;
        } catch (error) {
            this.showNotification('エラー', '接続に失敗しました', 'error');
            this.updateStatus('接続エラー', true);
        }
    }

    // データ接続のセットアップ
    setupDataConnection() {
        this.dataConnection.on('open', () => {
            this.updateStatus('データチャネル確立');
        });

        this.dataConnection.on('data', async data => {
            try {
                const decrypted = await CryptoUtil.decrypt(
                    this.encryptionKey,
                    data.iv,
                    data.encryptedData
                );
                const decodedData = new TextDecoder().decode(decrypted);
                this.handleReceivedData(JSON.parse(decodedData));
            } catch (error) {
                console.error('データ復号化エラー:', error);
            }
        });

        this.dataConnection.on('close', () => {
            this.updateStatus('データチャネル切断');
        });
    }

    // 通話処理
    handleCall(call) {
        this.currentCall = call;

        call.on('stream', stream => {
            this.elements.remoteVideo.srcObject = stream;
            this.updateStatus('通話中');
            this.startConnectionQualityMonitoring();
        });

        call.on('close', () => {
            this.disconnect();
        });

        call.peerConnection.oniceconnectionstatechange = () => {
            const state = call.peerConnection.iceConnectionState;
            this.updateConnectionQuality(state);
        };
    }

    // 接続品質のモニタリング
    startConnectionQualityMonitoring() {
        setInterval(() => {
            if (this.currentCall && this.currentCall.peerConnection) {
                this.currentCall.peerConnection.getStats().then(stats => {
                    stats.forEach(report => {
                        if (report.type === 'candidate-pair' && report.state === 'succeeded') {
                            const quality = this.calculateConnectionQuality(report);
                            this.elements.connectionQuality.textContent = quality;
                        }
                    });
                });
            }
        }, 1000);
    }

    // 接続品質の計算
    calculateConnectionQuality(stats) {
        if (stats.availableOutgoingBitrate) {
            const bitrate = stats.availableOutgoingBitrate / 1000000; // Mbps
            if (bitrate > 2) return '良好';
            if (bitrate > 1) return '普通';
            return '不安定';
        }
        return '計測中...';
    }

    // オーディオのトグル
    toggleAudio() {
        this.isAudioEnabled = !this.isAudioEnabled;
        this.localStream.getAudioTracks().forEach(track => {
            track.enabled = this.isAudioEnabled;
        });
        this.elements.toggleMicButton.classList.toggle('active', !this.isAudioEnabled);
        this.elements.toggleMicButton.querySelector('i').className = 
            this.isAudioEnabled ? 'fas fa-microphone' : 'fas fa-microphone-slash';
    }

    // ビデオのトグル
    toggleVideo() {
        this.isVideoEnabled = !this.isVideoEnabled;
        this.localStream.getVideoTracks().forEach(track => {
            track.enabled = this.isVideoEnabled;
        });
        this.elements.toggleVideoButton.classList.toggle('active', !this.isVideoEnabled);
        this.elements.toggleVideoButton.querySelector('i').className = 
            this.isVideoEnabled ? 'fas fa-video' : 'fas fa-video-slash';
    }

    // 切断処理
    disconnect() {
        if (this.currentCall) {
            this.currentCall.close();
        }
        if (this.dataConnection) {
            this.dataConnection.close();
        }
        this.elements.remoteVideo.srcObject = null;
        this.elements.connectButton.disabled = false;
        this.elements.disconnectButton.disabled = true;
        this.updateStatus('切断しました');
        this.elements.statusIndicator.classList.remove('connected');
    }

    // ステータス更新
    updateStatus(message, isError = false) {
        this.elements.connectionStatus.textContent = message;
        this.elements.statusIndicator.classList.toggle('connected', !isError);
        console.log('Status:', message);
    }

    // 接続品質の更新
    updateConnectionQuality(state) {
        let quality = '不明';
        switch (state) {
            case 'new':
            case 'checking':
                quality = '接続確認中...';
                break;
            case 'connected':
                quality = '良好';
                break;
            case 'completed':
                quality = '安定';
                break;
            case 'disconnected':
                quality = '切断';
                break;
            case 'failed':
                quality = '接続失敗';
                break;
        }
        this.elements.connectionQuality.textContent = quality;
    }

    // 通知の表示
    showNotification(title, message, type = 'info') {
        const modal = document.getElementById('notificationModal');
        const modalContent = modal.querySelector('.modal-content');
        const modalMessage = modal.querySelector('.modal-message');
        const modalIcon = modal.querySelector('.modal-icon');

        modalMessage.textContent = message;

        // アイコンの設定
        modalIcon.className = 'modal-icon fas';
        switch (type) {
            case 'success':
                modalIcon.classList.add('fa-check-circle');
                modalIcon.style.color = 'var(--success-color)';
                break;
            case 'error':
                modalIcon.classList.add('fa-exclamation-circle');
                modalIcon.style.color = 'var(--danger-color)';
                break;
            case 'warning':
                modalIcon.classList.add('fa-exclamation-triangle');
                modalIcon.style.color = 'var(--warning-color)';
                break;
            default:
                modalIcon.classList.add('fa-info-circle');
                modalIcon.style.color = 'var(--primary-color)';
        }

        modal.classList.add('visible');
        setTimeout(() => {
            modal.classList.remove('visible');
        }, 3000);
    }

    // 暗号化されたデータの送信
    async sendEncryptedData(data) {
        if (!this.dataConnection || !this.encryptionKey) return;

        try {
            const encrypted = await CryptoUtil.encrypt(
                this.encryptionKey,
                new TextEncoder().encode(JSON.stringify(data))
            );
            this.dataConnection.send({
                iv: encrypted.iv,
                encryptedData: encrypted.data
            });
        } catch (error) {
            console.error('暗号化エラー:', error);
        }
    }

    // 受信データの処理
    handleReceivedData(data) {
        // 受信データの処理をここに実装
        console.log('Received data:', data);
    }
}

// アプリケーションの初期化
window.addEventListener('DOMContentLoaded', () => {
    new SecureVideoChat();
});
