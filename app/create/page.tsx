"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

// ============================================================================
// Crypto utilities
// ============================================================================

const generatePassword = (): string => {
  const chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  const charsLength = chars.length;
  const maxValid = Math.floor(0xFFFFFFFF / charsLength) * charsLength;

  let password = "";
  const randomValues = new Uint32Array(32);
  crypto.getRandomValues(randomValues);

  let idx = 0;
  while (password.length < 16) {
    if (idx >= randomValues.length) {
      crypto.getRandomValues(randomValues);
      idx = 0;
    }
    const value = randomValues[idx++];
    if (value < maxValid) {
      password += chars.charAt(value % charsLength);
    }
  }
  return password;
};

const generateSeed = (): string => {
  const chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  const randomValues = new Uint8Array(12);
  crypto.getRandomValues(randomValues);
  return Array.from(randomValues)
    .map(v => chars[v % chars.length])
    .join("");
};

const arrayBufferToBase64 = (buffer: BufferSource): string => {
  const bytes =
    buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = "";
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary);
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

const encryptText = async (
  plaintext: string,
  password: string
): Promise<{
  ciphertext: string;
  iv: string;
  salt: string;
}> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await deriveKey(password, salt);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    salt: arrayBufferToBase64(salt),
  };
};

const toUrlSafe = (base64: string): string => {
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
};

// ============================================================================
// Shard creation (client-side) - must match /s/[id] page
// ============================================================================

const SHARD_COUNT = 4;
const MIN_SHARD_SIZE = 16;

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

function seededShuffle<T>(array: T[], seed: string): T[] {
  const result = [...array];

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

  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }

  return result;
}

function splitIntoShards(data: Uint8Array, shardCount: number, seed: string): Uint8Array[] {
  const totalLength = data.length;

  if (totalLength < shardCount * MIN_SHARD_SIZE) {
    const paddedData = new Uint8Array(shardCount * MIN_SHARD_SIZE);
    paddedData.set(data);
    const view = new DataView(paddedData.buffer);
    view.setUint32(paddedData.length - 4, data.length, true);
    return splitIntoShards(paddedData, shardCount, seed + ":padded");
  }

  let h = 0;
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(31, h) + seed.charCodeAt(i) | 0;
  }
  h = Math.imul(h, 0x5bd1e995) | 0;

  const random = () => {
    h |= 0;
    h = h + 0x6D2B79F5 | 0;
    let t = Math.imul(h ^ h >>> 15, 1 | h);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };

  const splitPoints: number[] = [0];
  let remaining = totalLength;

  for (let i = 0; i < shardCount - 1; i++) {
    const remainingShards = shardCount - i;
    const avgRemaining = remaining / remainingShards;
    const variance = avgRemaining * 0.5;
    const size = Math.floor(avgRemaining + (random() - 0.5) * variance);
    const clampedSize = Math.max(MIN_SHARD_SIZE, Math.min(remaining - MIN_SHARD_SIZE * (remainingShards - 1), size));
    splitPoints.push(splitPoints[splitPoints.length - 1] + clampedSize);
    remaining -= clampedSize;
  }
  splitPoints.push(totalLength);

  const shards: Uint8Array[] = [];
  for (let i = 0; i < shardCount; i++) {
    const start = splitPoints[i];
    const end = splitPoints[i + 1];
    shards.push(data.slice(start, end));
  }

  return shards;
}

async function createShards(
  encryptedData: string,
  iv: string,
  salt: string,
  seed: string
): Promise<string[]> {
  const ivBytes = fromBase64Url(iv);
  const saltBytes = fromBase64Url(salt);
  const ciphertextBytes = fromBase64Url(encryptedData);

  // Format: [ivLen:2][saltLen:2][iv][salt][ciphertext]
  const totalLength = 4 + ivBytes.length + saltBytes.length + ciphertextBytes.length;
  const combined = new Uint8Array(totalLength);
  const view = new DataView(combined.buffer);

  view.setUint16(0, ivBytes.length, true);
  view.setUint16(2, saltBytes.length, true);
  combined.set(ivBytes, 4);
  combined.set(saltBytes, 4 + ivBytes.length);
  combined.set(ciphertextBytes, 4 + ivBytes.length + saltBytes.length);

  // Split into shards
  const shards = splitIntoShards(combined, SHARD_COUNT, seed);

  // XOR each shard with derived key
  const xoredShards: Uint8Array[] = [];
  for (let i = 0; i < shards.length; i++) {
    const xorKey = await deriveXorKey(seed, i, shards[i].length);
    xoredShards.push(xorBytes(shards[i], xorKey));
  }

  // Shuffle shards
  const shuffledShards = seededShuffle(xoredShards, seed + ":shuffle");

  // Convert to base64
  return shuffledShards.map(s => toBase64Url(s));
}

// ============================================================================
// Icons
// ============================================================================

const LockIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
);

const LogoutIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
    <polyline points="16 17 21 12 16 7"/>
    <line x1="21" y1="12" x2="9" y2="12"/>
  </svg>
);

const CopyIcon = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
  </svg>
);

const CheckIcon = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);

const ShieldIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);

// ============================================================================
// Component
// ============================================================================

const MAX_SECRET_LENGTH = 50000;

const DURATIONS = [
  { value: "1", label: "1 hour", display: "1 hour" },
  { value: "6", label: "6 hours", display: "6 hours" },
  { value: "24", label: "24 hours", display: "24 hours" },
  { value: "72", label: "3 days", display: "3 days" },
  { value: "168", label: "1 week", display: "1 week" },
];

export default function SecretCreator() {
  const router = useRouter();
  const [secretText, setSecretText] = useState("");
  const [duration, setDuration] = useState("24");
  const [isCreating, setIsCreating] = useState(false);
  const [generatedLink, setGeneratedLink] = useState("");
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [error, setError] = useState("");
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [hoveredField, setHoveredField] = useState<string | null>(null);

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  };

  const createSecret = async () => {
    if (!secretText.trim()) {
      setError("Please enter a secret");
      return;
    }

    if (secretText.length > MAX_SECRET_LENGTH) {
      setError(`Secret is too long (max ${MAX_SECRET_LENGTH} characters)`);
      return;
    }

    setIsCreating(true);
    setError("");

    try {
      // 1. Generate password and seed
      const password = generatePassword();
      const seed = generateSeed();

      // 2. Encrypt the secret
      const { ciphertext, iv, salt } = await encryptText(secretText, password);

      // 3. Create shards
      const shards = await createShards(
        toUrlSafe(ciphertext),
        toUrlSafe(iv),
        toUrlSafe(salt),
        seed
      );

      // 4. Calculate expiration
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + parseInt(duration));

      // 5. Send shards to server
      const response = await fetch("/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          shards,
          expiresAt: expiresAt.getTime(),
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Failed to store secret");
      }

      const { id } = await response.json();

      // 6. Generate short URL with seed in hash
      const baseUrl = window.location.origin;
      const link = `${baseUrl}/s/${id}#${seed}`;

      setGeneratedLink(link);
      setGeneratedPassword(password);
      setSecretText("");
    } catch (err) {
      console.error("Create error:", err);
      setError(err instanceof Error ? err.message : "Failed to create secret");
    } finally {
      setIsCreating(false);
    }
  };

  const createNewSecret = () => {
    setGeneratedLink("");
    setGeneratedPassword("");
    setError("");
  };

  const copyToClipboard = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    }
  };

  const expirationLabel = DURATIONS.find(d => d.value === duration)?.label || "24 hours";

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        {/* Top Bar */}
        <div style={styles.topBar}>
          <div style={styles.badge}>
            <LockIcon />
            <span>Protected</span>
          </div>
          <button
            onClick={handleLogout}
            style={styles.logoutBtn}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = "var(--text-tertiary)";
              e.currentTarget.style.color = "var(--text-secondary)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = "var(--border-color)";
              e.currentTarget.style.color = "var(--text-tertiary)";
            }}
          >
            <LogoutIcon />
            <span>Logout</span>
          </button>
        </div>

        {/* Header */}
        <div style={styles.header}>
          {generatedLink ? (
            <>
              <div style={styles.successIcon}>
                <CheckIcon size={24} />
              </div>
              <h1 style={styles.title}>Secret Ready</h1>
              <p style={styles.subtitle}>
                Expires in {expirationLabel}
              </p>
            </>
          ) : (
            <>
              <h1 style={styles.title}>New Secret</h1>
              <p style={styles.subtitle}>
                Sharded encryption for maximum security
              </p>
            </>
          )}
        </div>

        {error && <div style={styles.error}>{error}</div>}

        {generatedLink ? (
          /* Success State */
          <div style={styles.successContent}>
            {/* Link Field */}
            <div style={styles.fieldGroup}>
              <div style={styles.fieldHeader}>
                <span style={styles.fieldLabel}>Share Link</span>
                {copiedField === "link" && (
                  <span style={styles.copiedBadge}>
                    <CheckIcon size={12} />
                    Copied
                  </span>
                )}
              </div>
              <button
                type="button"
                onClick={() => copyToClipboard(generatedLink, "link")}
                onMouseEnter={() => setHoveredField("link")}
                onMouseLeave={() => setHoveredField(null)}
                aria-label="Copy link to clipboard"
                style={{
                  ...styles.copyField,
                  ...(hoveredField === "link" ? styles.copyFieldHover : {}),
                  ...(copiedField === "link" ? styles.copyFieldCopied : {}),
                }}
              >
                <span style={styles.copyFieldText}>{generatedLink}</span>
                <span style={{
                  ...styles.copyIcon,
                  opacity: hoveredField === "link" || copiedField === "link" ? 1 : 0.5,
                }}>
                  {copiedField === "link" ? <CheckIcon size={18} /> : <CopyIcon size={18} />}
                </span>
              </button>
            </div>

            {/* Password Field */}
            <div style={styles.fieldGroup}>
              <div style={styles.fieldHeader}>
                <span style={styles.fieldLabel}>Password</span>
                {copiedField === "password" && (
                  <span style={styles.copiedBadge}>
                    <CheckIcon size={12} />
                    Copied
                  </span>
                )}
              </div>
              <button
                type="button"
                onClick={() => copyToClipboard(generatedPassword, "password")}
                onMouseEnter={() => setHoveredField("password")}
                onMouseLeave={() => setHoveredField(null)}
                aria-label="Copy password to clipboard"
                style={{
                  ...styles.copyField,
                  ...styles.copyFieldPassword,
                  ...(hoveredField === "password" ? styles.copyFieldHover : {}),
                  ...(copiedField === "password" ? styles.copyFieldCopied : {}),
                }}
              >
                <span style={styles.passwordText}>{generatedPassword}</span>
                <span style={{
                  ...styles.copyIcon,
                  opacity: hoveredField === "password" || copiedField === "password" ? 1 : 0.5,
                }}>
                  {copiedField === "password" ? <CheckIcon size={18} /> : <CopyIcon size={18} />}
                </span>
              </button>
            </div>

            {/* Security Note */}
            <p style={styles.securityNote}>
              Share link and password separately for security
            </p>

            {/* New Secret Button */}
            <button
              onClick={createNewSecret}
              style={styles.secondaryButton}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = "var(--bg-secondary)";
                e.currentTarget.style.borderColor = "var(--text-tertiary)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = "var(--bg-tertiary)";
                e.currentTarget.style.borderColor = "var(--border-color)";
              }}
            >
              Create another secret
            </button>
          </div>
        ) : (
          /* Create Form */
          <div style={styles.form}>
            {/* Secret Input */}
            <div style={styles.formGroup}>
              <label htmlFor="secret-content" style={styles.label}>Content</label>
              <textarea
                id="secret-content"
                value={secretText}
                onChange={(e) => setSecretText(e.target.value)}
                placeholder="Password, API key, or any sensitive data..."
                style={styles.textarea}
                onFocus={(e) => {
                  e.currentTarget.style.borderColor = "#0000FF";
                  e.currentTarget.style.boxShadow = "0 0 0 3px rgba(0, 0, 255, 0.1)";
                }}
                onBlur={(e) => {
                  e.currentTarget.style.borderColor = "var(--border-color)";
                  e.currentTarget.style.boxShadow = "none";
                }}
              />
              <div style={styles.charCount}>
                <span style={{
                  color: secretText.length > MAX_SECRET_LENGTH * 0.9
                    ? "var(--warning)"
                    : "var(--text-tertiary)"
                }}>
                  {secretText.length.toLocaleString()}
                </span>
                <span style={{ color: "var(--text-tertiary)" }}> / {MAX_SECRET_LENGTH.toLocaleString()}</span>
              </div>
            </div>

            {/* Duration Selector */}
            <div style={styles.formGroup}>
              <label id="duration-label" style={styles.label}>Expires after</label>
              <div style={styles.durationGrid} role="radiogroup" aria-labelledby="duration-label">
                {DURATIONS.map((d) => (
                  <button
                    key={d.value}
                    type="button"
                    role="radio"
                    aria-checked={duration === d.value}
                    onClick={() => setDuration(d.value)}
                    style={{
                      ...styles.durationOption,
                      ...(duration === d.value ? styles.durationOptionActive : {}),
                    }}
                    onMouseEnter={(e) => {
                      if (duration !== d.value) {
                        e.currentTarget.style.borderColor = "#0000FF";
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (duration !== d.value) {
                        e.currentTarget.style.borderColor = "var(--border-color)";
                      }
                    }}
                  >
                    {d.display}
                  </button>
                ))}
              </div>
            </div>

            {/* Submit Button */}
            <button
              onClick={createSecret}
              disabled={isCreating || !secretText.trim()}
              style={{
                ...styles.primaryButton,
                ...(isCreating || !secretText.trim() ? styles.primaryButtonDisabled : {}),
              }}
              onMouseEnter={(e) => {
                if (!isCreating && secretText.trim()) {
                  e.currentTarget.style.backgroundColor = "#0000CC";
                }
              }}
              onMouseLeave={(e) => {
                if (!isCreating && secretText.trim()) {
                  e.currentTarget.style.backgroundColor = "#0000FF";
                }
              }}
            >
              {isCreating ? (
                <span style={styles.loadingText}>Encrypting...</span>
              ) : (
                "Encrypt and create link"
              )}
            </button>

            {/* Security Info */}
            <div style={styles.securityInfo}>
              <div style={styles.securityItem}>
                <ShieldIcon />
                <span>4 encrypted shards stored separately</span>
              </div>
              <div style={styles.securityItem}>
                <span style={styles.securityDot} />
                AES-256 + XOR + random shuffle
              </div>
              <div style={styles.securityItem}>
                <span style={styles.securityDot} />
                Seed in URL hash (never sent to server)
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Styles
// ============================================================================

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    padding: "24px",
  },
  card: {
    width: "100%",
    maxWidth: "480px",
    backgroundColor: "var(--bg-secondary)",
    border: "1px solid var(--border-color)",
    borderRadius: "16px",
    padding: "28px",
  },
  topBar: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "28px",
  },
  badge: {
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    padding: "5px 10px",
    backgroundColor: "var(--bg-tertiary)",
    border: "1px solid var(--border-color)",
    borderRadius: "6px",
    fontSize: "12px",
    color: "var(--text-secondary)",
    fontWeight: 500,
  },
  logoutBtn: {
    padding: "6px 10px",
    backgroundColor: "transparent",
    color: "var(--text-tertiary)",
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: "var(--border-color)",
    borderRadius: "6px",
    fontSize: "12px",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    gap: "5px",
    transition: "all 0.15s ease",
  },
  header: {
    textAlign: "center",
    marginBottom: "28px",
  },
  successIcon: {
    width: "48px",
    height: "48px",
    borderRadius: "50%",
    backgroundColor: "rgba(34, 197, 94, 0.1)",
    color: "var(--success)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    margin: "0 auto 16px",
  },
  title: {
    fontSize: "22px",
    fontWeight: 600,
    color: "var(--text-primary)",
    marginBottom: "6px",
    letterSpacing: "-0.02em",
  },
  subtitle: {
    fontSize: "14px",
    color: "var(--text-tertiary)",
  },
  error: {
    padding: "12px 14px",
    backgroundColor: "var(--error-muted)",
    border: "1px solid rgba(239, 68, 68, 0.2)",
    borderRadius: "8px",
    color: "var(--error)",
    fontSize: "13px",
    marginBottom: "20px",
  },
  successContent: {
    display: "flex",
    flexDirection: "column",
    gap: "4px",
  },
  fieldGroup: {
    marginBottom: "16px",
  },
  fieldHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "8px",
  },
  fieldLabel: {
    fontSize: "12px",
    fontWeight: 600,
    color: "var(--text-secondary)",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
  },
  copiedBadge: {
    display: "inline-flex",
    alignItems: "center",
    gap: "4px",
    fontSize: "11px",
    color: "var(--success)",
    fontWeight: 500,
  },
  copyField: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "12px",
    padding: "14px 16px",
    backgroundColor: "var(--bg-tertiary)",
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: "var(--border-color)",
    borderRadius: "10px",
    cursor: "pointer",
    transition: "all 0.15s ease",
    width: "100%",
    textAlign: "left",
  },
  copyFieldHover: {
    borderColor: "#0000FF",
    backgroundColor: "var(--bg-primary)",
  },
  copyFieldCopied: {
    borderColor: "var(--success)",
    backgroundColor: "rgba(34, 197, 94, 0.05)",
  },
  copyFieldPassword: {
    fontFamily: "var(--font-geist-mono), monospace",
  },
  copyFieldText: {
    flex: 1,
    fontSize: "13px",
    color: "var(--text-primary)",
    fontFamily: "var(--font-geist-mono), monospace",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  passwordText: {
    flex: 1,
    fontSize: "15px",
    fontWeight: 600,
    color: "var(--text-primary)",
    letterSpacing: "2px",
  },
  copyIcon: {
    flexShrink: 0,
    color: "var(--text-secondary)",
    transition: "opacity 0.15s ease",
  },
  securityNote: {
    fontSize: "12px",
    color: "var(--text-tertiary)",
    textAlign: "center",
    marginTop: "8px",
    marginBottom: "24px",
  },
  secondaryButton: {
    width: "100%",
    padding: "12px 16px",
    backgroundColor: "var(--bg-tertiary)",
    color: "var(--text-primary)",
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: "var(--border-color)",
    borderRadius: "10px",
    fontSize: "14px",
    fontWeight: 500,
    cursor: "pointer",
    transition: "all 0.15s ease",
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: "4px",
  },
  formGroup: {
    marginBottom: "20px",
  },
  label: {
    display: "block",
    fontSize: "13px",
    fontWeight: 500,
    color: "var(--text-secondary)",
    marginBottom: "8px",
  },
  textarea: {
    width: "100%",
    padding: "14px 16px",
    backgroundColor: "var(--bg-tertiary)",
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: "var(--border-color)",
    borderRadius: "10px",
    color: "var(--text-primary)",
    fontSize: "14px",
    fontFamily: "var(--font-geist-mono), monospace",
    outline: "none",
    resize: "vertical",
    minHeight: "120px",
    transition: "border-color 0.15s ease, box-shadow 0.15s ease",
    lineHeight: 1.6,
  },
  charCount: {
    fontSize: "12px",
    marginTop: "8px",
    textAlign: "right",
  },
  durationGrid: {
    display: "flex",
    flexWrap: "wrap",
    gap: "8px",
  },
  durationOption: {
    padding: "10px 14px",
    backgroundColor: "var(--bg-tertiary)",
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: "var(--border-color)",
    borderRadius: "8px",
    cursor: "pointer",
    transition: "all 0.15s ease",
    fontSize: "13px",
    fontWeight: 500,
    color: "var(--text-secondary)",
  },
  durationOptionActive: {
    backgroundColor: "#0000FF",
    borderColor: "#0000FF",
    color: "white",
  },
  primaryButton: {
    width: "100%",
    padding: "14px 16px",
    backgroundColor: "#0000FF",
    color: "white",
    border: "none",
    borderRadius: "10px",
    fontSize: "14px",
    fontWeight: 600,
    cursor: "pointer",
    transition: "background-color 0.15s ease",
  },
  primaryButtonDisabled: {
    backgroundColor: "var(--bg-tertiary)",
    color: "var(--text-tertiary)",
    cursor: "not-allowed",
  },
  loadingText: {
    display: "inline-flex",
    alignItems: "center",
    gap: "8px",
  },
  securityInfo: {
    display: "flex",
    flexDirection: "column",
    gap: "8px",
    marginTop: "24px",
    padding: "16px",
    backgroundColor: "var(--bg-tertiary)",
    borderRadius: "10px",
  },
  securityItem: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    fontSize: "12px",
    color: "var(--text-tertiary)",
  },
  securityDot: {
    width: "6px",
    height: "6px",
    borderRadius: "50%",
    backgroundColor: "var(--success)",
    flexShrink: 0,
  },
};
