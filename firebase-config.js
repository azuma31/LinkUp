// =====================================================
// Firebase 設定ファイル
// =====================================================
// ★★★ ここを自分のFirebaseプロジェクトの設定に書き換えてください ★★★
//
// 1. Firebaseコンソール (https://console.firebase.google.com/) でプロジェクトを作成
// 2. 「Realtime Database」を有効化（テストモードで開始してOK）
// 3. 「プロジェクトの設定」→「全般」→「マイアプリ」でウェブアプリを追加
// 4. 表示されるfirebaseConfigオブジェクトの内容をここにコピー
//
// セキュリティルール例（最低限：認証なしでも自分のアプリだけ使う用途）:
// {
//   "rules": {
//     ".read": true,
//     ".write": true
//   }
// }
// ※本番運用では適切なルールを設定してください
// =====================================================

window.FIREBASE_CONFIG = {
    apiKey: "AIzaSyAVhJVvMFoQafCkkZmb4n8dXLQu7X-pke8",
    authDomain: "linkup5.firebaseapp.com",
    projectId: "linkup5",
    storageBucket: "linkup5.firebasestorage.app",
    messagingSenderId: "612158108179",
    appId: "1:612158108179:web:dd0b16a18bbbe8107ac5e6",
    measurementId: "G-ZZR9FV3DXJ"
};
