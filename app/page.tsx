"use client";

import { useState, useEffect } from "react";

const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return buffer;
};

const deriveKey = async (
  password: string,
  salt: BufferSource
): Promise<CryptoKey> => {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 250000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
};

const decryptText = async (
  ciphertext: string,
  iv: string,
  salt: string,
  password: string
): Promise<string> => {
  const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
  const ivBuffer = new Uint8Array(base64ToArrayBuffer(iv));
  const saltBuffer = new Uint8Array(base64ToArrayBuffer(salt));

  const key = await deriveKey(password, saltBuffer);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBuffer },
    key,
    ciphertextBuffer
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
};

const fromUrlSafe = (urlSafe: string): string => {
  if (urlSafe.length > 100000) {
    throw new Error("Data too large");
  }
  let base64 = urlSafe.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return base64;
};

const styles = {
  container: {
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column" as const,
    alignItems: "center",
    justifyContent: "center",
    padding: "24px",
  },
  card: {
    width: "100%",
    maxWidth: "420px",
    backgroundColor: "var(--bg-secondary)",
    border: "1px solid var(--border-color)",
    borderRadius: "var(--radius-lg)",
    padding: "32px",
  },
  header: {
    textAlign: "center" as const,
    marginBottom: "32px",
  },
  icon: {
    width: "48px",
    height: "48px",
    margin: "0 auto 16px",
    backgroundColor: "var(--accent-muted)",
    borderRadius: "12px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  title: {
    fontSize: "20px",
    fontWeight: 600,
    color: "var(--text-primary)",
    marginBottom: "8px",
  },
  subtitle: {
    fontSize: "14px",
    color: "var(--text-secondary)",
  },
  label: {
    display: "block",
    fontSize: "13px",
    fontWeight: 500,
    color: "var(--text-secondary)",
    marginBottom: "8px",
  },
  input: {
    width: "100%",
    padding: "12px 14px",
    backgroundColor: "var(--bg-tertiary)",
    border: "1px solid var(--border-color)",
    borderRadius: "var(--radius-md)",
    color: "var(--text-primary)",
    fontSize: "14px",
    outline: "none",
    transition: "border-color 0.15s ease",
  },
  button: {
    width: "100%",
    padding: "12px 16px",
    backgroundColor: "var(--accent)",
    color: "white",
    border: "none",
    borderRadius: "var(--radius-md)",
    fontSize: "14px",
    fontWeight: 500,
    cursor: "pointer",
    transition: "background-color 0.15s ease",
    marginTop: "16px",
  },
  buttonDisabled: {
    backgroundColor: "var(--bg-tertiary)",
    color: "var(--text-tertiary)",
    cursor: "not-allowed",
  },
  error: {
    padding: "12px 14px",
    backgroundColor: "var(--error-muted)",
    border: "1px solid rgba(239, 68, 68, 0.2)",
    borderRadius: "var(--radius-md)",
    color: "var(--error)",
    fontSize: "13px",
    marginBottom: "16px",
  },
  success: {
    marginTop: "24px",
  },
  secretBox: {
    padding: "16px",
    backgroundColor: "var(--bg-tertiary)",
    border: "1px solid var(--border-color)",
    borderRadius: "var(--radius-md)",
    fontFamily: "var(--font-geist-mono), monospace",
    fontSize: "13px",
    color: "var(--text-primary)",
    whiteSpace: "pre-wrap" as const,
    wordBreak: "break-word" as const,
    maxHeight: "300px",
    overflowY: "auto" as const,
  },
  copyButton: {
    width: "100%",
    padding: "10px 16px",
    backgroundColor: "var(--bg-tertiary)",
    color: "var(--text-primary)",
    border: "1px solid var(--border-color)",
    borderRadius: "var(--radius-md)",
    fontSize: "13px",
    fontWeight: 500,
    cursor: "pointer",
    marginTop: "12px",
    transition: "all 0.15s ease",
  },
  info: {
    marginTop: "24px",
    padding: "14px",
    backgroundColor: "var(--bg-tertiary)",
    borderRadius: "var(--radius-md)",
    fontSize: "12px",
    color: "var(--text-tertiary)",
  },
  infoList: {
    margin: "8px 0 0 16px",
    padding: 0,
    listStyle: "disc",
  },
  empty: {
    textAlign: "center" as const,
    padding: "48px 24px",
  },
  emptyIcon: {
    width: "64px",
    height: "64px",
    margin: "0 auto 20px",
    backgroundColor: "var(--bg-tertiary)",
    borderRadius: "16px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "28px",
    color: "var(--text-tertiary)",
  },
};

export default function SecretViewer() {
  const [hasSecret, setHasSecret] = useState(false);
  const [inputPassword, setInputPassword] = useState("");
  const [decryptedSecret, setDecryptedSecret] = useState("");
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [error, setError] = useState("");
  const [isExpired, setIsExpired] = useState(false);
  const [copied, setCopied] = useState(false);
  const [urlData, setUrlData] = useState<{
    ciphertext: string;
    iv: string;
    salt: string;
    expires: string;
  } | null>(null);

  useEffect(() => {
    const hash = window.location.hash.substring(1);
    if (hash) {
      try {
        const params = new URLSearchParams(hash);
        const ciphertext = params.get("c");
        const iv = params.get("i");
        const salt = params.get("s");
        const expires = params.get("e");

        if (ciphertext && iv && salt && expires) {
          const expiresTimestamp = parseInt(expires, 10);
          if (isNaN(expiresTimestamp) || expiresTimestamp < 0) {
            throw new Error("Invalid expiration");
          }

          setUrlData({
            ciphertext: fromUrlSafe(ciphertext),
            iv: fromUrlSafe(iv),
            salt: fromUrlSafe(salt),
            expires,
          });
          setHasSecret(true);

          const expiresDate = new Date(expiresTimestamp);
          if (new Date() > expiresDate) {
            setIsExpired(true);
            setError("This secret has expired");
          }
        }
      } catch {
        setError("Invalid URL");
      }
    }
  }, []);

  const decryptSecret = async () => {
    if (!urlData || !inputPassword.trim()) {
      setError("Password required");
      return;
    }

    setIsDecrypting(true);
    setError("");
    setDecryptedSecret("");

    try {
      const decrypted = await decryptText(
        urlData.ciphertext,
        urlData.iv,
        urlData.salt,
        inputPassword
      );
      setDecryptedSecret(decrypted);
    } catch {
      setError("Incorrect password");
    } finally {
      setIsDecrypting(false);
    }
  };

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(decryptedSecret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!hasSecret) {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <div style={styles.empty}>
            <div style={styles.emptyIcon}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <h2 style={{ ...styles.title, marginBottom: "12px" }}>No secret detected</h2>
            <p style={styles.subtitle}>
              Use the complete link that was shared with you to view the encrypted message.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.header}>
          <div style={styles.icon}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <h1 style={styles.title}>Encrypted Message</h1>
          <p style={styles.subtitle}>Enter the password to decrypt</p>
        </div>

        {error && (
          <div style={styles.error}>{error}</div>
        )}

        {!decryptedSecret && !isExpired && (
          <div>
            <label style={styles.label}>Password</label>
            <input
              type="password"
              value={inputPassword}
              onChange={(e) => setInputPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && decryptSecret()}
              placeholder="Enter the password"
              autoFocus
              style={styles.input}
            />
            <button
              onClick={decryptSecret}
              disabled={isDecrypting || !inputPassword.trim()}
              style={{
                ...styles.button,
                ...(isDecrypting || !inputPassword.trim() ? styles.buttonDisabled : {}),
              }}
            >
              {isDecrypting ? "Decrypting..." : "Decrypt"}
            </button>
          </div>
        )}

        {decryptedSecret && (
          <div style={styles.success}>
            <label style={{ ...styles.label, color: "var(--success)" }}>
              Decrypted successfully
            </label>
            <div style={styles.secretBox}>{decryptedSecret}</div>
            <button onClick={copyToClipboard} style={styles.copyButton}>
              {copied ? "Copied!" : "Copy to clipboard"}
            </button>
          </div>
        )}

        <div style={styles.info}>
          <strong style={{ color: "var(--text-secondary)" }}>Security</strong>
          <ul style={styles.infoList}>
            <li>AES-256 client-side decryption</li>
            <li>No data sent to server</li>
            <li>Zero-knowledge architecture</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
