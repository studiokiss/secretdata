"use client";

interface Option {
  value: string;
  label: string;
}

interface OptionGroupProps {
  id: string;
  label: string;
  options: Option[];
  value: string;
  onChange: (value: string) => void;
}

export default function OptionGroup({ id, label, options, value, onChange }: OptionGroupProps) {
  const labelId = `${id}-label`;

  return (
    <div style={styles.formGroup}>
      <label id={labelId} style={styles.label}>{label}</label>
      <div style={styles.grid} role="radiogroup" aria-labelledby={labelId}>
        {options.map((option) => {
          const isActive = value === option.value;
          return (
            <button
              key={option.value}
              type="button"
              role="radio"
              aria-checked={isActive}
              onClick={() => onChange(option.value)}
              style={{ ...styles.option, ...(isActive ? styles.optionActive : {}) }}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.borderColor = "#0000FF";
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.borderColor = "var(--border-color)";
              }}
            >
              {option.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
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
  grid: {
    display: "flex",
    flexWrap: "wrap",
    gap: "8px",
  },
  option: {
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
  optionActive: {
    backgroundColor: "#0000FF",
    borderColor: "#0000FF",
    color: "white",
  },
};
