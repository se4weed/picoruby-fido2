# PicoRuby FIDO2 Authenticator MVP

USB I/Oから独立して検証できる、最小構成のFIDO2 Authenticator実装です。

> [!IMPORTANT]
> 現在は実験用MVPです。秘密鍵とPIN hashを通常のFlashへ保存するため、Secure Element相当の耐タンパ性はありません。

## PicoRubyへの追加

PicoRubyのbuild configへこのmrbgemを追加します。

```ruby
conf.gem github: "se4weed/picoruby-fido2"
```

現時点ではR2P2のUSB composite deviceへFIDO HID interfaceを追加するため、同梱の`picoruby-usb-fido.patch`もPicoRuby repositoryへ適用する必要があります。USB拡張部分の完全なmrbgem化と専用firmware化は今後の課題です。

## ディレクトリ構成

```text
lib/fido2/
├── cbor/           # CTAP2で使用するCBOR codec
├── crypto/         # ES256、SHA-256、乱数、COSE Key
├── credential/     # Credentialモデルと永続化
├── ctap/           # AuthenticatorとCTAP command dispatcher
├── ctaphid/        # 64-byte HID reportの分割・再構築
└── user_presence/  # 物理ボタンへ差し替える確認インターフェース
```

実行環境はPicoRubyです。SHA-256とP-256はこのmrbgem内のC実装、ClientPIN Protocol 1のAES-256-CBCはMbedTLSを使用します。乱数源は`picoruby-rng`、永続化は`picoruby-vfs`を使用します。CRubyのOpenSSL、JSON、Base64、FileUtilsには依存しません。USB HID descriptorと実際のread/write callbackはこのディレクトリの対象外です。

CTAP2のこの対応範囲で必要なハッシュはSHA-256だけです。署名はP-256 + SHA-256（ES256）、RP ID hashとclient data hashもSHA-256を使用し、SHA-1は使用しません。

## 対応範囲

- `authenticatorGetInfo`
- `authenticatorMakeCredential`（ES256、none attestation）
- `authenticatorGetAssertion`（discoverable / non-discoverable credential）
- `authenticatorClientPIN` Protocol 1（PIN設定・変更、試行回数、PIN token）
- CTAPHID INIT、PING、CBOR、CANCEL
- Credentialのファイル永続化と署名カウンター

PIN tokenによるUser VerificationとDiscoverable Credentialに対応します。CTAP1/U2F、ClientPIN Protocol 2、指紋などの内蔵UVには対応しません。

## テスト

`picoruby-fido2`を組み込んだPicoRubyバイナリで、次を実行します。

```sh
picoruby test/runtime_runner.rb
```

このrunnerはPicoRuby VM上でSHA-256、ES256、COSE Key、CBOR、MakeCredential/GetAssertion、CTAPHID fragmentationを検証します。

暗号のネイティブ実装は`src/fido2_crypto.c`、P-256のベンダーコードとライセンスは`vendor/p256-m/`にあります。

暗号APIは状態を持たないmodule methodとして公開します。

```ruby
digest = FIDO2::Crypto.sha256("abc")
key = FIDO2::Crypto.generate_key_pair
signature = FIDO2::Crypto.sign(key, "message")
FIDO2::Crypto.verify(key.public_key, signature, "message")
```

## USB実機試験

R2P2 firmwareはkeyboard、mouse、consumer controlに加えて、64-byte IN/OUT reportを持つFIDO HID interfaceを公開します。`example/usb_authenticator.rb`をR2P2へ転送して実行すると、CTAPHID要求をCTAP dispatcherへ中継します。

```sh
./usb_authenticator.rb
```

この例はCredentialを`/home/fido2-credentials`、PIN状態を`/home/fido2-credentials/pin-state.f2p`へ保存し、Discoverable CredentialとPINを再起動後も利用できます。User PresenceにはGPIO 15とGNDの間に接続したタクトスイッチを使用します。PINはブラウザで入力し、物理ボタンは操作の承認に使用します。

Credentialの作成時と使用時には、シリアルコンソールへCredential ID、RP ID hash、User IDの長さ、署名カウンタを出力します。秘密鍵とUser ID本体は出力しません。
