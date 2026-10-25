# PicoRuby FIDO2 Hardware Token

## 1. 概要

Raspberry Pi Pico 2（RP2350）とPicoRubyを用いて、USB接続のFIDO2ハードウェアトークンを実装する。

本実装では、WebAuthn対応ブラウザから外部Authenticatorとして認識され、WebサービスへのCredential登録および認証を行えることを目標とする。

開発は以下の2段階に分ける。

1. R2P2上でFIDO2のプロトコル処理、暗号処理、Credential管理、User Presenceを検証する
2. 検証済みの実装を専用Firmwareへ組み込み、USB HID経由でCTAP2 Authenticatorとして動作させる

最初からFIDO2仕様全体を実装するのではなく、Credentialの登録と認証ができる最小のFIDO2 Security KeyをMVPとする。

## 2. 背景

FIDO2では、Webサービスが秘密情報そのものを受け取るのではなく、Authenticator内部で生成・保持された秘密鍵による署名を利用してユーザーを認証する。

外部ハードウェアAuthenticatorの場合、ブラウザおよびOSとAuthenticatorの間ではCTAPが使用される。

本プロジェクトでは、このAuthenticator部分をPicoRubyで実装する。

PicoRubyにはRP2040/RP2350向けのGPIO、RNG、Flash filesystem、Mbed TLS等の基盤が存在するため、FIDO2の上位プロトコルをRubyで記述できる可能性がある。

一方、USB HID descriptorやUSB packet処理など、ハードウェアに密接する部分についてはRubyだけで実装することにこだわらず、Pico SDK / TinyUSB等を利用したC実装との境界を設ける。

## 3. Goal

- Raspberry Pi Pico 2をUSB FIDO2 AuthenticatorとしてPCから認識できる
- WebAuthnを利用してCredentialを登録できる
- 登録したCredentialを利用して認証できる
- Credentialごとに異なる秘密鍵を生成する
- 秘密鍵をデバイス外部へ送信しない
- ES256（ECDSA P-256 + SHA-256）を用いた署名ができる
- User Presenceを物理ボタンで確認できる
- Credentialを再起動後も保持できる
- Discoverable Credentialを保存し、RP IDだけで認証できる
- Passkeyのusername-less login要求を処理できる
- ClientPIN PIN/UV Auth Protocol 1によるPIN設定とUser Verificationを処理できる
- PINまたはUser Verificationを必須とするWebAuthnサービスでCredentialを登録・認証できる
- CTAPの主要ロジックをRubyで実装する
- R2P2上でUSB以外の主要ロジックを単体検証できる
- 最終的にR2P2とは独立したFIDO2専用UF2を生成できる

## 4. Non-Goal

初期実装では以下を対象外とする。

- FIDO Alliance Certification取得
- NFC
- BLE
- Fingerprint等の生体認証
- PIN/UV Auth Protocol 2
- 生体認証などPIN以外のUser Verification
- CTAP1 / U2F互換
- Credential Management
- Enterprise Attestation
- 複数Authenticator間でのCredential同期
- Secure Elementの利用
- 物理攻撃に対する完全な秘密鍵保護
- CTAP仕様の全Command実装

MVPではnon-discoverable credentialとdiscoverable credentialを対象とし、User Verificationが必要な場合はClientPIN PIN/UV Auth Protocol 1によるPIN認証を使用する。

## 5. 仕様

### 5.1 システム構成

全体構成は以下とする。

```text
Web Application
      |
      | WebAuthn
      v
Browser / OS
      |
      | CTAP2
      | USB HID
      v
+-----------------------------+
| PicoRuby FIDO2 Authenticator|
|                             |
| CTAPHID Transport           |
|          |                  |
| CTAP Dispatcher             |
|          |                  |
| +--------+--------+         |
| |                 |         |
| MakeCredential GetAssertion |
| |                 |         |
| +--------+--------+         |
|          |                  |
| Authenticator Core          |
|   |       |       |         |
| Crypto  Storage   UP        |
+-----------------------------+
```

WebAuthnの処理そのものはブラウザ側が担当する。

PicoRuby側ではCTAP Authenticatorを実装する。

### 5.2 実装レイヤ

実装は以下のレイヤに分割する。

```text
USB HID
  ↓
CTAPHID
  ↓
CBOR
  ↓
CTAP Command
  ↓
Authenticator
  ↓
Crypto / CredentialStore / UserPresence
```

RubyとCの境界は原則として、

```text
protocol / state machine
    Ruby

hardware / crypto primitive
    C
```

とする。

可能な限りCTAPの状態遷移やCBORデータの構築はRubyで実装する。

USB device implementation、乱数生成、ECDSA等についてRubyから十分なAPIが提供されていない場合はPicoRuby mrbgemとしてC bindingを追加する。

### 5.3 CTAPHID

USB接続ではFIDO HID deviceとして認識される必要がある。

最低限以下を実装する。

```text
CTAPHID_INIT
CTAPHID_CBOR
CTAPHID_PING
CTAPHID_CANCEL
CTAPHID_ERROR
CTAPHID_KEEPALIVE
```

CTAPHIDでは64 byte HID Reportを使用し、大きなCTAP messageを複数packetへ分割する。
各Reportの長さは文字数ではなく`String#bytesize`を基準にし、64 byteへゼロ埋めする。PicoRubyはUTF-8文字列を有効にしているため、バイナリpayloadに対して文字幅基準の`String#ljust`を使用してはならない。

Transport層では、

```text
HID packet
    ↓
CTAPHID message reassembly
    ↓
CTAP CBOR request
```

および逆方向の処理を担当する。

CTAPHIDのpacket parsingとmessage reassemblyはUSBに依存しないため、Ruby単体でテスト可能な実装とする。

USB I/Oのみplatform依存とする。

### 5.4 CBOR

CTAP2 command payloadではCBORを使用する。

MVPで必要な型に限定して実装する。

```text
Integer
Byte String
Text String
Array
Map
Boolean
nil
```

既存のPicoRuby向けCBOR実装が利用可能であれば利用する。

利用できない場合は、CTAP2で必要なsubsetのみを扱う小さなCBOR encoder / decoderを実装する。

CBOR implementation自体にFIDO2固有のロジックを持たせない。

### 5.5 authenticatorGetInfo

ブラウザがAuthenticatorの能力を取得するため、`authenticatorGetInfo` を実装する。

MVPでは概ね以下の能力を返す。

```text
versions:
  FIDO_2_0
  FIDO_2_1

extensions:
  []

aaguid:
  project固有値

options:
  up: true
  uv: false
  rk: true
  clientPin: false（未設定）/ true（設定済み）

pinUvAuthProtocols:
  [1]

maxMsgSize:
  実装可能なサイズ
```

実際にadvertiseするCTAP versionは、実装済みCommandおよび仕様適合性を確認したうえで決定する。

未実装の機能をadvertiseしてはならない。

### 5.6 authenticatorMakeCredential

Credential登録時に使用する。

処理フローを以下とする。

```text
request
  ↓
parameter validation
  ↓
clientDataHash
rp
user
pubKeyCredParams
options
  ↓
User Presence
  ↓
key pair generation
  ↓
credential_id generation
  ↓
CredentialStore.save
  ↓
authenticatorData generation
  ↓
attestation response
```

MVPでは以下のアルゴリズムのみサポートする。

```text
alg = -7
ES256
ECDSA
NIST P-256
SHA-256
```

Credentialごとに新しい鍵ペアを生成する。

`options.rk`がtrueの場合はDiscoverable Credentialとして保存する。内蔵UV modalityを持たないため`options.uv`がtrueの場合は`CTAP2_ERR_UNSUPPORTED_OPTION`を返す。`pinUvAuthParam`が指定された場合はClientPINで取得した`pinUvAuthToken`を用いて要求を検証し、成功した場合だけUser Verification済みとしてAuthenticator DataのUV flagを立てる。

秘密鍵はAuthenticator内部へ保存する。

公開鍵はCOSE_Key形式へ変換してresponseへ含める。

### 5.7 authenticatorGetAssertion

認証時に使用する。

処理フローを以下とする。

```text
request
  ↓
rpId
clientDataHash
allowList（任意）
pinUvAuthProtocol / pinUvAuthParam（PIN利用時）
  ↓
credential_id lookup
  ↓
RP ID validation
  ↓
User Presence
  ↓
authenticatorData generation
  ↓
signature generation
  ↓
response
```

署名対象はCTAP/WebAuthn仕様に従い、

```text
authenticatorData || clientDataHash
```

とする。

秘密鍵はCredentialStoreからCrypto layerへ渡すが、USBやCTAP responseへ含めない。

### 5.8 Credential ID

MVPではCredentialをRP2350のFlashへ保存する。

Credentialは概念的に以下の情報を持つ。

```text
Credential
  id
  rp_id_hash
  private_key
  public_key
  sign_count
```

Credential IDは暗号学的に十分なランダム値から生成する。

例:

```text
credential_id = random_bytes(32)
```

Webサービス側はこのCredential IDを保存する。

GetAssertion時に`allowList`が指定された場合は、Credential IDから対応するCredentialを検索する。

`allowList`が省略または空の場合は、RP ID hashに一致するDiscoverable Credentialを検索する。MVPでは同一RPに対する複数アカウントの選択と`authenticatorGetNextAssertion`は対象外とし、最初に見つかったCredentialを返す。

### 5.9 CredentialStore

永続化APIはFIDO2のprotocol implementationから分離する。

想定APIは以下とする。

```ruby
CredentialStore.save(credential)

CredentialStore.find(credential_id)

CredentialStore.delete(credential_id)

CredentialStore.increment_sign_count(credential_id)

CredentialStore.find_by_rp_id_hash(rp_id_hash)
```

R2P2上ではfilesystemを利用して実装する。

最終FirmwareでもLittleFS等のFlash storageを利用できる構造とする。

保存形式は内部実装とし、CTAP implementationから直接filesystemへアクセスしない。

PIN状態はCredentialとは異なるライフサイクルを持つため、`PINStore`として分離する。

```ruby
PINStore.load
PINStore.save(pin_hash:, retries:)
PINStore.clear
```

PIN状態の更新は途中状態を正常データとして読み込まない形式とし、checksumまたは同等の破損検出を行う。

### 5.10 Crypto

Crypto layerでは最低限以下を提供する。

```ruby
Crypto.random_bytes(length)

Crypto.sha256(data)

Crypto.generate_key_pair

Crypto.sign(private_key, data)

Crypto.public_key_to_cose(public_key)

Crypto.ecdh(private_key, peer_public_key)

Crypto.hmac_sha256(key, data)

Crypto.aes_256_cbc_encrypt(key, iv, data)

Crypto.aes_256_cbc_decrypt(key, iv, data)
```

鍵アルゴリズムはES256のみとする。

SHA-256、HMAC-SHA-256、AES-256-CBCとECDSA/ECDH P-256の鍵生成・署名・検証・共有秘密導出は`picoruby-fido2`内のC bindingとして提供する。P-256は固定幅整数で動作する同梱実装、AES-256-CBCはPicoRubyのMbedTLSを使用し、CRuby OpenSSLへ依存しない。Ruby層は秘密鍵32 byte、非圧縮点の座標64 byte、DER形式のECDSA署名を扱う。

RP2350にはハードウェア乱数源が存在するため、最終FirmwareではPico SDKの安全な乱数APIを利用する。

疑似乱数生成器のみを秘密鍵生成へ使用してはならない。

### 5.11 User Presence

MVPでは物理ボタンによってUser Presenceを確認する。

MakeCredentialおよびGetAssertion時に、

```text
LED ON
   ↓
button press wait
   ↓
LED OFF
   ↓
operation continue
```

とする。

User Presence確認待ちの間、USB側へ必要に応じてCTAPHID_KEEPALIVEを返す。

一定時間操作されなかった場合はtimeoutとして処理を中断する。

PINによるUser VerificationはClientPIN PIN/UV Auth Protocol 1で実装する。物理ボタンによるUser PresenceはPIN検証とは独立して要求し、UV済みであることをUP確認の代替にしない。

### 5.12 ClientPIN PIN/UV Auth Protocol 1

PINによるUser Verificationのため、CTAP2の`authenticatorClientPIN`（Command `0x06`）とPIN/UV Auth Protocol 1を実装する。

サポートするsubCommandは以下とする。

```text
getRetries
getKeyAgreement
setPIN
changePIN
getPINToken
```

Authenticatorは起動時に一時的なP-256 key agreement鍵ペアと32 byteの`pinUvAuthToken`を生成する。Clientとの共有秘密はECDHのx座標をSHA-256へ入力して導出する。

Protocol 1の暗号処理は以下とする。

```text
sharedSecret = SHA-256(ECDH x-coordinate)
pinUvAuthParam = left16(HMAC-SHA-256(key, message))
暗号化 = AES-256-CBC(sharedSecret, IV=16 byte zero)
```

PINの平文は保存しない。PIN設定時は復号したUTF-8 PINを検証し、`left16(SHA-256(pin))`だけをFlashへ保存する。PINは4 Unicode code point以上かつUTF-8で63 byte以下とし、`newPinEnc`のゼロpaddingを除去して評価する。

`setPIN`はPIN未設定時だけ許可する。`changePIN`は現在のPIN hashと`pinUvAuthParam`を検証してから更新する。`getPINToken`はPIN検証成功時だけ暗号化したtokenを返す。

MakeCredentialでは`pinUvAuthParam = left16(HMAC-SHA-256(pinUvAuthToken, clientDataHash))`を検証する。GetAssertionも同じ検証を行う。有効なparamを受理した場合はAuthenticator DataのUV flagを立て、無効または不足している場合は要求内容に応じたCTAPエラーを返す。

PIN状態として以下を永続化する。

```text
pinHash（16 byte）
pinRetries
```

PIN試行失敗時は`pinRetries`を減らし、成功時は規定値へ戻す。連続失敗に対する一時ブロックと、retry枯渇時の`CTAP2_ERR_PIN_BLOCKED`を実装する。電源再投入で一時ブロックは解除してよいが、永続化されたretry枯渇状態を解除してはならない。

PIN未設定時のGetInfoは`clientPin: false`、設定後は`clientPin: true`を返す。PIN/UV Auth Protocol 2、permission付きtoken、UV modalityは対象外とし、未実装機能をadvertiseしない。

### 5.13 Attestation

MVPではAttestationの実装を最小化する。

FIDO2 Security KeyとしてブラウザとのEnd-to-End検証を成立させることを優先し、製造元を証明するAttestation Certificate infrastructureは構築しない。

Attestation formatについてはブラウザとの互換性を確認し、`none`または自己署名可能な形式から最も単純な方式を選択する。

Attestation formatは`none`とする。正式なAuthenticator AttestationおよびAAGUID管理はMVP後の課題とする。

### 5.14 R2P2による開発

R2P2は開発・検証環境として利用する。

R2P2そのものを最終Firmwareにはしない。

R2P2上では以下を優先して検証する。

```text
SHA-256
random bytes
ECDSA P-256
GPIO button
LED
Flash persistence
CBOR
CTAPHID packet parser
CTAP command parser
CredentialStore
MakeCredential
GetAssertion
```

USB HIDがなくてもテストできるよう、CTAP coreは以下のようなAPIとして実装する。

```ruby
response =
  FIDO2::Authenticator.call(command, payload)
```

これによりR2P2 shellから、

```text
CTAP request
    ↓
Ruby method
    ↓
CTAP response
```

を直接試すことができる。

### 5.15 R2P2用テストTransport

開発初期はUSBの代わりにDebug Transportを用意する。

例えば、

```text
hex encoded request
        ↓
Serial
        ↓
CTAP Dispatcher
        ↓
hex encoded response
```

という形式とする。

PC側でテストデータを生成し、R2P2へ送ることでAuthenticator Coreを検証する。

これによりUSB HID実装前にFIDO2ロジックを完成させる。

### 5.16 専用Firmware

Authenticator CoreがR2P2上で動作した後、FIDO2専用Firmwareを作成する。

最終FirmwareではR2P2 shell、IRB等の開発機能を含めない。

構成は概ね以下とする。

```text
Pico SDK
TinyUSB
PicoRuby
  |
  +-- FIDO2 Ruby implementation
  |
  +-- native mrbgems
       |
       +-- USB HID
       +-- ECDSA
       +-- RNG
       +-- Flash
```

起動後はRuby側のFIDO2 main loopを直接開始する。

```text
boot
 ↓
USB initialize
 ↓
CredentialStore initialize
 ↓
FIDO2 Authenticator loop
```

### 5.17 USB実装

USB HIDについてはPicoRubyのRuby codeだけで実装する必要はない。

TinyUSB / Pico SDK側でFIDO HID interfaceを定義し、Rubyから以下のようなAPIのみ利用できる構成を目指す。

```ruby
USB::FIDO.read_report

USB::FIDO.write_report(data)
```

USB descriptor、endpoint、interrupt handler等はC側で管理する。

CTAPHID protocol自体はRuby側で処理する。

これによりUSB implementationとFIDO2 protocol implementationを分離する。

### 5.18 セキュリティ

本プロジェクトはまずFIDO2 protocolの実装検証を目的とする。

RP2350の通常Flashへ秘密鍵を保存する場合、

```text
秘密鍵がUSB通信へ出ない
```

ことは保証できても、

```text
物理的にデバイスを解析されても秘密鍵が取得できない
```

ことまでは保証できない。

そのためMVPをSecure Element相当の製品として扱ってはならない。

将来的には以下を検討する。

```text
RP2350 security features
secure boot
flash encryption相当の構成
OTP
TrustZone
external Secure Element
```

これらはFIDO2 protocol implementationとは別レイヤとして扱う。

PIN、`pinHash`、ECDH共有秘密、`pinUvAuthToken`はログへ出力しない。一時的な平文PINと秘密値を保持するbufferは利用後に上書きし、Ruby VMおよびC binding上で不要な複製を作らない。Flash更新中の電源断でPIN retry状態が巻き戻らない保存方式を採用する。

### 5.19 エラー処理

各レイヤでエラーを変換する。

```text
Hardware error
      ↓
Authenticator error
      ↓
CTAP error code
      ↓
CTAPHID response
```

Rubyの例外をそのままUSBへ伝播させない。

不正なCBOR、未知のCommand、存在しないCredential等について適切なCTAP errorを返す。

ClientPINでは少なくとも`CTAP2_ERR_PIN_INVALID`、`CTAP2_ERR_PIN_AUTH_INVALID`、`CTAP2_ERR_PIN_NOT_SET`、`CTAP2_ERR_PIN_REQUIRED`、`CTAP2_ERR_PIN_POLICY_VIOLATION`、`CTAP2_ERR_PIN_AUTH_BLOCKED`、`CTAP2_ERR_PIN_BLOCKED`を状態に応じて返す。

## 6. ディレクトリ構成

初期案を以下とする。

```text
fido2-picoruby/
├── mrblib/
│   └── fido2/
│       ├── authenticator.rb
│       ├── ctap.rb
│       ├── ctaphid.rb
│       ├── cbor.rb
│       ├── credential.rb
│       ├── credential_store.rb
│       ├── crypto.rb
│       └── user_presence.rb
│
├── mrbgems/
│   ├── picoruby-fido-usb/
│   └── picoruby-fido-crypto/
│
├── test/
│   ├── ctap_test.rb
│   ├── ctaphid_test.rb
│   ├── cbor_test.rb
│   ├── credential_store_test.rb
│   └── authenticator_test.rb
│
├── examples/
│   └── r2p2/
│       └── app.rb
│
└── build_config/
    └── pico2.rb
```

実際には既存PicoRuby repositoryへ直接mrbgemとして実装する可能性があるため、repository構成は実装開始時に決定する。

## 7. 開発フェーズ

### 7.1 Phase 1: R2P2 Hardware Spike

R2P2上で以下を確認する。

```text
GPIO
button
LED
RNG
SHA-256
Flash persistence
```

特にECDSA P-256の鍵生成と署名がRubyから利用可能か確認する。

利用できなければ最初のnative extensionとしてECDSA bindingを実装する。

このPhaseではFIDO2はまだ実装しない。

### 7.2 Phase 2: Authenticator Core

USBを使用せず以下を実装する。

```text
CBOR
Credential
CredentialStore
Crypto
authenticatorGetInfo
authenticatorMakeCredential
authenticatorGetAssertion
```

固定requestを入力し、正しいresponseを生成できることを確認する。

### 7.3 Phase 3: CTAPHID

CTAPHID packet parser / serializerを実装する。

実USBはまだ使用せず、unit testで64 byte packetを入出力する。

message fragmentationおよびreassemblyをテストする。

### 7.4 Phase 4: USB HID

TinyUSB等を利用してFIDO HID device interfaceを追加する。

PCからFIDO deviceとしてenumerateされることを確認する。

CTAPHIDとAuthenticator Coreを接続する。

### 7.5 Phase 5: WebAuthn End-to-End

ブラウザから、

```text
navigator.credentials.create()
```

を実行する。

Pico 2のボタンを押す。

Credential登録が成功することを確認する。

続いて、

```text
navigator.credentials.get()
```

を実行する。

同じCredentialによる署名検証が成功することを確認する。

ここをMVP完成条件とする。

### 7.6 Phase 6: ClientPIN Protocol 1

USBを使用しないAuthenticator Coreのテストから実装を開始する。

```text
P-256 ECDH
HMAC-SHA-256
AES-256-CBC
PINStore
authenticatorClientPIN
pinUvAuthParam validation
UV flag
PIN retry / block state
```

既知の暗号test vectorで各primitiveを検証した後、ClientPINのsubCommandを状態遷移ごとにテストする。続いてR2P2実機でPIN設定、再起動後のPIN状態、PIN付きMakeCredential/GetAssertionを確認し、PIN必須のWebAuthnサービスでEnd-to-Endテストする。

### 7.7 Phase 7: Hardening

MVP後に以下を検討する。

```text
Credential Management
Attestation
Secure storage
CTAP conformance
Security review
```

## 8. MVP完成条件

以下のシナリオがChrome等のWebAuthn対応ブラウザから成功すること。

```text
Pico 2を接続
 ↓
WebサイトでSecurity Key登録
 ↓
Pico 2のLED点灯
 ↓
物理ボタンを押す
 ↓
Credential生成
 ↓
登録成功
 ↓
Pico 2を再起動
 ↓
同じWebサイトでログイン
 ↓
Pico 2のLED点灯
 ↓
物理ボタンを押す
 ↓
ECDSA署名
 ↓
ログイン成功
```

Pico 2を再起動してもCredentialが利用できることを必須とする。

加えて、以下のClientPINシナリオが成功することを必須とする。

```text
PIN未設定状態でPINを設定
 ↓
GetInfoがclientPin: trueを返す
 ↓
PIN必須サイトでCredentialを登録
 ↓
pinUvAuthParamを検証してUV flagを設定
 ↓
PINを使用して認証
 ↓
再起動後も同じPINで認証
```

誤ったPINでretryが減少し、正しいPINで回復すること、一時ブロックとretry枯渇による永続ブロックが規定どおり動作することも確認する。

## 9. 懸念事項

最大の技術的不確実性は以下である。

```text
PicoRubyからECDSA P-256を十分に扱えるか
USB FIDO HID interfaceをどのレイヤで実装するか
RubyでCTAP処理した場合のRAM使用量
Flashへ秘密鍵を保存する際の安全性
ブラウザが要求するAuthenticator capabilityの最小集合
ClientPINの一時秘密値を限られたRAMで安全に扱えるか
PIN retry状態を電源断に対して安全に更新できるか
```

この中でも、

```text
ECDSA P-256
USB HID
```

の2点はプロジェクト成立可否へ直接影響する。

したがって実装開始時にはFIDO2 protocol全体を書くのではなく、この2点を最初にSpikeする。

## 10. 実装開始順

最初に作るものはFIDO2ではなく、

```text
R2P2
 ↓
random 32 bytes生成
 ↓
P-256 key pair生成
 ↓
SHA-256
 ↓
ECDSA sign
 ↓
ECDSA verify
 ↓
Flashへprivate key保存
 ↓
再起動
 ↓
同じprivate keyで再度sign
```

という小さなプログラムとする。

これが成立した後、

```text
CredentialStore
 ↓
MakeCredential
 ↓
GetAssertion
 ↓
CTAPHID
 ↓
USB
 ↓
ClientPIN Protocol 1
 ↓
PIN必須WebAuthn End-to-End
```

の順番で実装する。

これによりUSB、FIDO2、暗号、Flashの問題を同時にデバッグすることを避ける。
