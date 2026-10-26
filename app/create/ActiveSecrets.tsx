"use client";

import { useCallback, useEffect, useState } from "react";

interface ActiveSecret {
  id: string;
  label: string;
  createdAt: number;
  expiresAt: number;
  maxViews: number | null;
  remainingViews: number | null;
}

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

function formatTimeLeft(expiresAt: number): string {
  const msLeft = expiresAt - Date.now();
  if (msLeft >= DAY_MS) return `${Math.floor(msLeft / DAY_MS)} d`;
  if (msLeft >= HOUR_MS) return `${Math.floor(msLeft / HOUR_MS)} h`;
  return `${Math.max(1, Math.floor(msLeft / MINUTE_MS))} min`;
}

interface ActiveSecretsProps {
  // Changes whenever a secret is created, to reload the list
  refreshKey: string;
}

export default function ActiveSecrets({ refreshKey }: ActiveSecretsProps) {
  const [secrets, setSecrets] = useState<ActiveSecret[] | null>(null);
  const [error, setError] = useState("");
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadSecrets = useCallback(async () => {
    try {
      const response = await fetch("/api/secrets", { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setSecrets(data.secrets);
      setError("");
    } catch (err) {
      console.error("List error:", err);
      setError("Failed to load active links");
    }
  }, []);

  useEffect(() => {
    loadSecrets();
  }, [loadSecrets, refreshKey]);

  const deleteSecret = async (id: string) => {
    setDeletingId(id);
    try {
      const response = await fetch(`/api/secrets/${id}`, { method: "DELETE" });
      // 404: already expired or read to the end, the reload below drops it anyway
      if (!response.ok && response.status !== 404) {
        throw new Error(`HTTP ${response.status}`);
      }
      await loadSecrets();
    } catch (err) {
      console.error("Delete error:", err);
      setError("Failed to delete the link");
    } finally {
      setDeletingId(null);
      setConfirmingId(null);
    }
  };

  return (
    <section style={styles.card} aria-labelledby="active-links-title">
      <h2 id="active-links-title" style={styles.title}>Active links</h2>

      {error && <div style={styles.error}>{error}</div>}

      {secrets === null && !error && <p style={styles.empty}>Loading...</p>}
      {secrets?.length === 0 && <p style={styles.empty}>No active link</p>}

      <ul style={styles.list}>
        {secrets?.map((secret) => (
          <ActiveSecretRow
            key={secret.id}
            secret={secret}
            isConfirming={confirmingId === secret.id}
            isDeleting={deletingId === secret.id}
            onAskConfirm={() => setConfirmingId(secret.id)}
            onCancel={() => setConfirmingId(null)}
            onConfirm={() => deleteSecret(secret.id)}
          />
        ))}
      </ul>
    </section>
  );
}

interface ActiveSecretRowProps {
  secret: ActiveSecret;
  isConfirming: boolean;
  isDeleting: boolean;
  onAskConfirm: () => void;
  onCancel: () => void;
  onConfirm: () => void;
}

function ActiveSecretRow({
  secret, isConfirming, isDeleting, onAskConfirm, onCancel, onConfirm,
}: ActiveSecretRowProps) {
  return (
    <li style={styles.row}>
      <div style={styles.info}>
        <span style={styles.label}>{secret.label || "Untitled"}</span>
        <span style={styles.meta}>
          {secret.id} · expires in {formatTimeLeft(secret.expiresAt)} ·{" "}
          {secret.maxViews === null
            ? "unlimited views"
            : `${secret.remainingViews}/${secret.maxViews} views left`}
        </span>
      </div>
      {isConfirming ? (
        <div style={styles.actions}>
          <button type="button" onClick={onConfirm} disabled={isDeleting} style={styles.dangerButton}>
            {isDeleting ? "Deleting..." : "Confirm"}
          </button>
          <button type="button" onClick={onCancel} disabled={isDeleting} style={styles.button}>
            Cancel
          </button>
        </div>
      ) : (
        <button
          type="button"
          onClick={onAskConfirm}
          aria-label={`Delete link ${secret.label || secret.id}`}
          style={styles.button}
        >
          Delete
        </button>
      )}
    </li>
  );
}

const styles: Record<string, React.CSSProperties> = {
  card: {
    width: "100%",
    maxWidth: "480px",
    marginTop: "16px",
    backgroundColor: "var(--bg-secondary)",
    border: "1px solid var(--border-color)",
    borderRadius: "16px",
    padding: "20px 28px",
  },
  title: {
    fontSize: "15px",
    fontWeight: 600,
    color: "var(--text-primary)",
    margin: "0 0 12px",
  },
  error: {
    padding: "10px 12px",
    marginBottom: "12px",
    backgroundColor: "rgba(239, 68, 68, 0.1)",
    borderRadius: "8px",
    color: "var(--error)",
    fontSize: "13px",
  },
  empty: {
    fontSize: "13px",
    color: "var(--text-tertiary)",
    margin: 0,
  },
  list: {
    listStyle: "none",
    margin: 0,
    padding: 0,
  },
  row: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "12px",
    padding: "10px 0",
    borderTop: "1px solid var(--border-color)",
  },
  info: {
    display: "flex",
    flexDirection: "column",
    gap: "2px",
    minWidth: 0,
  },
  label: {
    fontSize: "14px",
    color: "var(--text-primary)",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  meta: {
    fontSize: "12px",
    color: "var(--text-tertiary)",
    fontFamily: "var(--font-geist-mono), monospace",
  },
  actions: {
    display: "flex",
    gap: "6px",
    flexShrink: 0,
  },
  button: {
    padding: "6px 10px",
    backgroundColor: "var(--bg-tertiary)",
    border: "1px solid var(--border-color)",
    borderRadius: "6px",
    fontSize: "12px",
    color: "var(--text-secondary)",
    cursor: "pointer",
    flexShrink: 0,
  },
  dangerButton: {
    padding: "6px 10px",
    backgroundColor: "var(--error)",
    border: "1px solid var(--error)",
    borderRadius: "6px",
    fontSize: "12px",
    color: "white",
    cursor: "pointer",
  },
};
