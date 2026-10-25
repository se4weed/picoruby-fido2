"use client";

import { useEffect, useState } from "react";

type SavedCredential = { id: string; createdAt: string };
type UserVerificationRequirement = "required" | "preferred" | "discouraged";
const STORAGE_KEY = "r2p2-webauthn-credential";

function userVerificationFromQuery(): UserVerificationRequirement {
  const value = new URLSearchParams(location.search).get("uv");
  if (value === "required" || value === "preferred") return value;
  return "discouraged";
}

function randomBytes(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function toBase64Url(value: ArrayBuffer) {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export default function Home() {
  const [credential, setCredential] = useState<SavedCredential | null>(null);
  const [userVerification, setUserVerification] = useState<UserVerificationRequirement>("discouraged");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("R2P2を接続し、デバイス側のAuthenticatorを起動してください。");
  const [detail, setDetail] = useState("");

  useEffect(() => {
    queueMicrotask(() => {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) setCredential(JSON.parse(saved));
      setUserVerification(userVerificationFromQuery());
    });
  }, []);

  async function register() {
    setBusy(true);
    setDetail("");
    setStatus("ブラウザで「セキュリティ キー」を選択してください…");
    try {
      const result = (await navigator.credentials.create({ publicKey: {
        challenge: randomBytes(32),
        rp: { id: location.hostname, name: "R2P2 WebAuthn Lab" },
        user: { id: randomBytes(32), name: "r2p2-user", displayName: "R2P2 Test User" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        timeout: 60_000,
        attestation: "none",
        authenticatorSelection: {
          authenticatorAttachment: "cross-platform",
          residentKey: "required",
          requireResidentKey: true,
          userVerification,
        },
      } })) as PublicKeyCredential | null;
      if (!result) throw new Error("credentialが返されませんでした");
      const saved = { id: toBase64Url(result.rawId), createdAt: new Date().toISOString() };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(saved));
      setCredential(saved);
      setStatus("登録成功 — R2P2がcredentialを作成しました。");
      setDetail(`credential ID: ${saved.id}`);
    } catch (error) {
      const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      setStatus("登録できませんでした。");
      setDetail(message);
    } finally { setBusy(false); }
  }

  async function authenticate() {
    if (!credential) return;
    setBusy(true);
    setDetail("");
    setStatus("R2P2へ署名要求を送信しています…");
    try {
      const result = (await navigator.credentials.get({ publicKey: {
        challenge: randomBytes(32),
        rpId: location.hostname,
        timeout: 60_000,
        userVerification,
      } })) as PublicKeyCredential | null;
      if (!result) throw new Error("assertionが返されませんでした");
      const response = result.response as AuthenticatorAssertionResponse;
      setStatus("認証成功 — R2P2がassertionへ署名しました。");
      setDetail(`signature: ${toBase64Url(response.signature)}`);
    } catch (error) {
      const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      setStatus("認証できませんでした。");
      setDetail(message);
    } finally { setBusy(false); }
  }

  function forget() {
    localStorage.removeItem(STORAGE_KEY);
    setCredential(null);
    setStatus("ブラウザ側のcredential IDを削除しました。");
    setDetail("R2P2側のMemoryStoreは、スクリプトを再起動すると消去されます。");
  }

  return <main>
    <section className="hero">
      <div className="eyebrow"><span className="dot" /> PicoRuby Hardware Lab</div>
      <h1>R2P2<br /><em>WebAuthn</em> Demo</h1>
      <p className="lead">Passkey保存先ではなく、外付けFIDO2セキュリティキーとしてR2P2を直接テストします。</p>
    </section>
    <section className="panel" aria-labelledby="lab-title">
      <div className="panelHeader"><div><p className="step">LIVE TEST</p><h2 id="lab-title">Credential ceremony</h2></div><div className={`state ${credential ? "ready" : "idle"}`}>{credential ? "REGISTERED" : "NOT REGISTERED"}</div></div>
      <div className="requirements"><span>USB / cross-platform</span><span>ES256</span><span>resident key: required</span><span>UV: {userVerification}</span></div>
      <div className="actions">
        <button className="primary" onClick={register} disabled={busy}><b>01</b><span>{credential ? "別のcredentialを登録" : "R2P2を登録"}<small>navigator.credentials.create()</small></span></button>
        <button className="secondary" onClick={authenticate} disabled={busy || !credential}><b>02</b><span>R2P2で認証<small>navigator.credentials.get()</small></span></button>
      </div>
      <div className="terminal" aria-live="polite"><div className="terminalBar"><i /><i /><i /><span>WEBAUTHN EVENT LOG</span></div><p><strong>STATUS</strong>{status}</p>{detail && <code>{detail}</code>}</div>
      {credential && <button className="forget" onClick={forget} disabled={busy}>ブラウザ側の登録情報を削除</button>}
    </section>
    <aside><strong>実験条件</strong><p>このページはブラウザAPIの疎通確認用です。サーバーによるattestation・署名検証は行いません。</p></aside>
  </main>;
}
