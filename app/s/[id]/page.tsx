"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";

// ============================================================================
// Crypto utilities (must match create page)
// ============================================================================

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
  let base64 = urlSafe.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return base64;
};

// ============================================================================
// Shard reconstruction (client-side)
// ============================================================================

function fromBase64Url(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  const binary = atob(base64);
  const result = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    result[i] = binary.charCodeAt(i);
  }
  return result;
}

function toBase64Url(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function deriveXorKey(seed: string, shardIndex: number, length: number): Promise<Uint8Array> {
  const encoder = new TextEncoder();

  const result = new Uint8Array(length);
  let offset = 0;
  let counter = 0;

  while (offset < length) {
    const counterData = encoder.encode(`${seed}:${shardIndex}:${counter}`);
    const counterHash = await crypto.subtle.digest("SHA-256", counterData);
    const counterArray = new Uint8Array(counterHash);

    const copyLength = Math.min(counterArray.length, length - offset);
    result.set(counterArray.slice(0, copyLength), offset);
    offset += copyLength;
    counter++;
  }

  return result;
}

function xorBytes(data: Uint8Array, key: Uint8Array): Uint8Array {
  const result = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ key[i % key.length];
  }
  return result;
}

function seededUnshuffle<T>(array: T[], seed: string): T[] {
  const n = array.length;

  let h = 0;
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(31, h) + seed.charCodeAt(i) | 0;
  }

  const random = () => {
    h |= 0;
    h = h + 0x6D2B79F5 | 0;
    let t = Math.imul(h ^ h >>> 15, 1 | h);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };

  const swaps: [number, number][] = [];
  for (let i = n - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    swaps.push([i, j]);
  }

  const result = [...array];
  for (let i = swaps.length - 1; i >= 0; i--) {
    const [a, b] = swaps[i];
    [result[a], result[b]] = [result[b], result[a]];
  }

  return result;
}

async function reconstructFromShards(
  shards: string[],
  seed: string
): Promise<{ ciphertext: string; iv: string; salt: string }> {
  const shuffledShards = shards.map(s => fromBase64Url(s));
  const xoredShards = seededUnshuffle(shuffledShards, seed + ":shuffle");

  const reconstructedShards: Uint8Array[] = [];
  for (let i = 0; i < xoredShards.length; i++) {
    const xorKey = await deriveXorKey(seed, i, xoredShards[i].length);
    reconstructedShards.push(xorBytes(xoredShards[i], xorKey));
  }

  const totalLength = reconstructedShards.reduce((sum, s) => sum + s.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const shard of reconstructedShards) {
    combined.set(shard, offset);
    offset += shard.length;
  }

  const view = new DataView(combined.buffer);
  const ivLen = view.getUint16(0, true);
  const saltLen = view.getUint16(2, true);

  const iv = combined.slice(4, 4 + ivLen);
  const salt = combined.slice(4 + ivLen, 4 + ivLen + saltLen);
  const ciphertext = combined.slice(4 + ivLen + saltLen);

  return {
    ciphertext: toBase64Url(ciphertext),
    iv: toBase64Url(iv),
    salt: toBase64Url(salt),
  };
}

// ============================================================================
// Styles
// ============================================================================

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
    borderRadius: "16px",
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
    backgroundColor: "rgba(0, 0, 255, 0.1)",
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
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: "var(--border-color)",
    borderRadius: "8px",
    color: "var(--text-primary)",
    fontSize: "14px",
    outline: "none",
  },
  button: {
    width: "100%",
    padding: "12px 16px",
    backgroundColor: "#0000FF",
    color: "white",
    border: "none",
    borderRadius: "8px",
    fontSize: "14px",
    fontWeight: 500,
    cursor: "pointer",
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
    borderRadius: "8px",
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
    borderRadius: "8px",
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
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: "var(--border-color)",
    borderRadius: "8px",
    fontSize: "13px",
    fontWeight: 500,
    cursor: "pointer",
    marginTop: "12px",
  },
  info: {
    marginTop: "24px",
    padding: "14px",
    backgroundColor: "var(--bg-tertiary)",
    borderRadius: "8px",
    fontSize: "12px",
    color: "var(--text-tertiary)",
  },
  infoList: {
    margin: "8px 0 0 16px",
    padding: 0,
    listStyle: "disc",
  },
  loading: {
    textAlign: "center" as const,
    padding: "24px",
  },
  spinner: {
    width: "32px",
    height: "32px",
    border: "3px solid var(--border-color)",
    borderTopColor: "#0000FF",
    borderRadius: "50%",
    margin: "0 auto 16px",
    animation: "spin 1s linear infinite",
  },
};

// ============================================================================
// Component
// ============================================================================

export default function ShortUrlViewer() {
  const params = useParams();
  const secretId = params.id as string;

  const [status, setStatus] = useState<"loading" | "ready" | "decrypted" | "error" | "expired">("loading");
  const [shards, setShards] = useState<string[] | null>(null);
  const [seed, setSeed] = useState<string | null>(null);
  const [inputPassword, setInputPassword] = useState("");
  const [decryptedSecret, setDecryptedSecret] = useState("");
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  // Fetch shards on mount
  useEffect(() => {
    const fetchShards = async () => {
      try {
        // Get seed from hash
        const hash = window.location.hash.substring(1);
        if (!hash) {
          setError("Missing decryption key in URL");
          setStatus("error");
          return;
        }
        setSeed(hash);

        // Fetch shards from API
        const response = await fetch(`/api/secrets/${secretId}`);

        if (response.status === 404) {
          setError("Secret not found or expired");
          setStatus("expired");
          return;
        }

        if (!response.ok) {
          throw new Error("Failed to fetch secret");
        }

        const data = await response.json();
        setShards(data.shards);
        setStatus("ready");
      } catch (err) {
        console.error("Fetch error:", err);
        setError("Failed to load secret");
        setStatus("error");
      }
    };

    fetchShards();
  }, [secretId]);

  const decryptSecret = async () => {
    if (!shards || !seed || !inputPassword.trim()) {
      setError("Password required");
      return;
    }

    setIsDecrypting(true);
    setError("");

    try {
      // Reconstruct encrypted data from shards
      const { ciphertext, iv, salt } = await reconstructFromShards(shards, seed);

      // Decrypt
      const decrypted = await decryptText(
        fromUrlSafe(ciphertext),
        fromUrlSafe(iv),
        fromUrlSafe(salt),
        inputPassword
      );

      setDecryptedSecret(decrypted);
      setStatus("decrypted");
    } catch (err) {
      console.error("Decrypt error:", err);
      setError("Incorrect password or corrupted data");
    } finally {
      setIsDecrypting(false);
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(decryptedSecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = decryptedSecret;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // Loading state
  if (status === "loading") {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <div style={styles.loading}>
            <div style={styles.spinner} />
            <p style={styles.subtitle}>Loading secret...</p>
          </div>
        </div>
      </div>
    );
  }

  // Error/Expired state
  if (status === "error" || status === "expired") {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <div style={styles.header}>
            <div style={{ ...styles.icon, backgroundColor: "rgba(239, 68, 68, 0.1)" }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--error)" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
              </svg>
            </div>
            <h1 style={styles.title}>
              {status === "expired" ? "Secret Expired" : "Error"}
            </h1>
            <p style={styles.subtitle}>{error}</p>
          </div>
        </div>
      </div>
    );
  }

  // Ready to decrypt / Decrypted
  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.header}>
          <div style={styles.icon}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0000FF" strokeWidth="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <h1 style={styles.title}>Encrypted Message</h1>
          <p style={styles.subtitle}>
            {status === "decrypted" ? "Decrypted successfully" : "Enter the password to decrypt"}
          </p>
        </div>

        {error && <div style={styles.error}>{error}</div>}

        {status === "ready" && (
          <div>
            <label style={styles.label} htmlFor="password-input">Password</label>
            <input
              id="password-input"
              type="password"
              value={inputPassword}
              onChange={(e) => setInputPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && decryptSecret()}
              placeholder="Enter the password"
              autoFocus
              style={styles.input}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "#0000FF";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "var(--border-color)";
              }}
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

        {status === "decrypted" && (
          <div style={styles.success}>
            <label style={{ ...styles.label, color: "var(--success)" }}>
              Secret content
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
            <li>Sharded + XOR encryption</li>
            <li>AES-256 client-side decryption</li>
            <li>Zero-knowledge architecture</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
