import React, { type ReactNode } from "react";

export type StatusTone = "idle" | "busy" | "success" | "warning" | "error";

export interface NavItem {
  href: string;
  label: string;
}

export function AppShell({
  product,
  context,
  network,
  nav,
  currentPath,
  onNavigate,
  children,
  footer,
}: {
  product: string;
  context: string;
  network: string;
  nav: NavItem[];
  currentPath: string;
  onNavigate(href: string): void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="app-frame">
      <header className="site-header">
        <button className="brand" onClick={() => onNavigate("/")} aria-label={`${product} home`}>
          <img src="/logo.svg" alt="" />
          <span>
            <b>{product}</b>
            <small>{context}</small>
          </span>
        </button>
        <nav aria-label="Primary navigation">
          {nav.map((item) => (
            <button
              key={item.href}
              className={currentPath === item.href ? "nav-link active" : "nav-link"}
              onClick={() => onNavigate(item.href)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <span className="network-badge">
          <i />
          {network}
        </span>
      </header>
      <div className="shell-body">{children}</div>
      <footer className="site-footer">
        <span>Private identity. Portable account.</span>
        <span>{footer ?? <a href="/privacy.html">Privacy</a>}</span>
      </footer>
    </div>
  );
}

export function PageIntro({
  eyebrow,
  title,
  description,
  aside,
}: {
  eyebrow: string;
  title: string;
  description: ReactNode;
  aside?: ReactNode;
}) {
  return (
    <header className="page-intro">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {aside && <div className="page-intro-aside">{aside}</div>}
    </header>
  );
}

export function StatusPanel({
  tone,
  label = "Status",
  children,
}: {
  tone: StatusTone;
  label?: string;
  children: ReactNode;
}) {
  return (
    <div className="status-panel" data-tone={tone} role={tone === "error" ? "alert" : "status"}>
      <span className="status-mark" aria-hidden="true" />
      <div>
        <small>{label}</small>
        <p>{children}</p>
      </div>
    </div>
  );
}

export function Steps({ steps, active }: { steps: string[]; active: number }) {
  return (
    <ol
      className="steps"
      aria-label="Progress"
      style={{ "--step-count": steps.length } as React.CSSProperties}
    >
      {steps.map((step, index) => (
        <li key={step} data-state={index < active ? "done" : index === active ? "active" : "next"}>
          <span>{index < active ? "✓" : index + 1}</span>
          <b>{step}</b>
        </li>
      ))}
    </ol>
  );
}

export function Card({
  title,
  eyebrow,
  children,
  className = "",
}: {
  title?: string;
  eyebrow?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`surface-card ${className}`.trim()}>
      {(eyebrow || title) && (
        <header>
          {eyebrow && <span>{eyebrow}</span>}
          {title && <h2>{title}</h2>}
        </header>
      )}
      {children}
    </section>
  );
}

export function KeyValue({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="key-value">
      <small>{label}</small>
      <span className={mono ? "mono" : ""}>{value}</span>
    </div>
  );
}

export function AddressDisplay({ label, value }: { label: string; value: string }) {
  const copy = () => void navigator.clipboard?.writeText(value);
  return (
    <div className="address-display">
      <div>
        <small>{label}</small>
        <code>{value}</code>
      </div>
      <button className="icon-button" onClick={copy} aria-label={`Copy ${label}`}>
        Copy
      </button>
    </div>
  );
}

export function TechnicalDetails({
  summary = "Technical details",
  children,
}: {
  summary?: string;
  children: ReactNode;
}) {
  return (
    <details className="technical-details">
      <summary>{summary}</summary>
      <div>{children}</div>
    </details>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-orbit" />
      <h2>{title}</h2>
      <p>{children}</p>
      {action}
    </div>
  );
}
