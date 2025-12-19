"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

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
    maxWidth: "380px",
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
  formGroup: {
    marginBottom: "16px",
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
    marginTop: "8px",
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
    textAlign: "center" as const,
  },
  footer: {
    marginTop: "24px",
    textAlign: "center" as const,
    fontSize: "12px",
    color: "var(--text-tertiary)",
  },
};

// Validate redirect URL to prevent open redirect attacks
function getSafeRedirect(): string {
  if (typeof window === 'undefined') return '/create';

  const params = new URLSearchParams(window.location.search);
  const redirect = params.get('redirect');

  // Only allow relative paths starting with /
  if (redirect && redirect.startsWith('/') && !redirect.startsWith('//')) {
    // Additional check: no protocol in path
    if (!redirect.includes(':')) {
      return redirect;
    }
  }

  return '/create';
}

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Authentication failed");
        return;
      }

      // Safe redirect after login
      const redirectTo = getSafeRedirect();
      router.push(redirectTo);
      router.refresh();
    } catch {
      setError("Connection error");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.header}>
          <div style={styles.icon}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2">
              <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/>
              <polyline points="10 17 15 12 10 7"/>
              <line x1="15" y1="12" x2="3" y2="12"/>
            </svg>
          </div>
          <h1 style={styles.title}>Admin Login</h1>
          <p style={styles.subtitle}>Sign in to access the admin area</p>
        </div>

        {error && <div style={styles.error}>{error}</div>}

        <form onSubmit={handleSubmit}>
          <div style={styles.formGroup}>
            <label style={styles.label}>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              autoComplete="username"
              autoFocus
              style={styles.input}
            />
          </div>

          <div style={styles.formGroup}>
            <label style={styles.label}>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              autoComplete="current-password"
              style={styles.input}
            />
          </div>

          <button
            type="submit"
            disabled={isLoading || !username || !password}
            style={{
              ...styles.button,
              ...(isLoading || !username || !password ? styles.buttonDisabled : {}),
            }}
          >
            {isLoading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <div style={styles.footer}>
          Protected area. Unauthorized access is prohibited.
        </div>
      </div>
    </div>
  );
}
