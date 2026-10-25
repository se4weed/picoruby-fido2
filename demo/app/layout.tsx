import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "R2P2 WebAuthn Demo",
  description: "PicoRuby R2P2を外付けFIDO2セキュリティキーとしてテストするWebAuthnデモ",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="ja"><body>{children}</body></html>;
}
