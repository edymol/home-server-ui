"use client";

import { useState, useEffect, useCallback, useRef } from "react";

/* ════════════════════════════════════════════════════
   TAILSCALE ACCESS MANAGER — Security-Hardened
   ACL control for Proxmox cluster
   Light / warm industrial aesthetic
   ════════════════════════════════════════════════════ */

// ─── Theme / Design Tokens ───

const THEME = {
  colors: {
    bg: "#f5f3ef",
    surface: "#fff",
    surfaceAlt: "#faf8f5",
    border: "#e5e1db",
    borderLight: "#f0ece6",
    borderInput: "#d6d0c6",
    muted: "#e8e4de",

    text: "#1e1b16",
    textSecondary: "#374151",
    textMuted: "#6b7280",
    textFaint: "#9ca3af",

    primary: "#2563eb",
    primaryLight: "#dbeafe",
    primaryBg: "#eff6ff",

    success: "#16a34a",
    successDark: "#15803d",
    successBg: "#f0fdf4",
    successBorder: "#bbf7d0",

    danger: "#ef4444",
    dangerDark: "#b91c1c",
    dangerDeep: "#991b1b",
    dangerBg: "#fef2f2",
    dangerBorder: "#fecaca",

    warning: "#d97706",
    warningDark: "#a16207",
    warningDeep: "#92400e",
    warningBg: "#fffbeb",
    warningBorder: "#fde68a",
    warningLight: "#fef3c7",

    purple: "#7c3aed",
    purpleBg: "#f8f7ff",
    purpleBorder: "#c7d2fe",
    purpleText: "#a5b4fc",

    infoBg: "#eff6ff",

    toastOk: "#1a7a3a",
    toastWarn: "#a65d00",
    toastError: "#b83232",

    lockdown: "#7f1d1d",
    lockdownBg: "#450a0a",
  },
  fonts: {
    body: "'DM Sans', sans-serif",
    mono: "'IBM Plex Mono', monospace",
  },
  radii: { sm: 4, md: 6, lg: 8, xl: 10, xxl: 12 },
  shadows: {
    modal: "0 20px 60px rgba(0,0,0,.15)",
    toast: "0 4px 20px rgba(0,0,0,.15)",
    tab: "0 1px 3px rgba(0,0,0,.08)",
  },
};

// ─── Validation Helpers ───

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const NAME_FORBIDDEN_CHARS = /[<>{}"'`\\]/;
const EXPECTED_SUBNET = "10.0.0";

function isValidEmail(email) {
  return EMAIL_RE.test(email.trim());
}

function isValidIPv4(ip) {
  if (!IPV4_RE.test(ip)) return false;
  return ip.split(".").every((octet) => {
    const n = parseInt(octet, 10);
    return n >= 0 && n <= 255;
  });
}

function isReservedIP(ip) {
  return ["0.0.0.0", "127.0.0.1", "255.255.255.255", "10.0.0.255", "10.0.0.0"].includes(ip);
}

function isInExpectedSubnet(ip) {
  return ip.startsWith(EXPECTED_SUBNET + ".");
}

function isValidName(name) {
  const trimmed = name.trim();
  return trimmed.length >= 2 && trimmed.length <= 64 && !NAME_FORBIDDEN_CHARS.test(trimmed);
}

function sanitizeName(name) {
  return name.trim().replace(/[\x00-\x1f]/g, "");
}

// ─── Security Constants ───

const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
const SESSION_CHECK_INTERVAL_MS = 30 * 1000;
const EXPIRY_CHECK_INTERVAL_MS = 60 * 1000;
const RATE_LIMIT_MAX_PUSHES = 3;
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

const PROTECTED_CONTAINERS = ["ct105"]; // Tailscale exit node — never grant to non-admins
const FORBIDDEN_PORTS = [3100]; // Access Manager UI — reserved

const PORT_DEFINITIONS = [
  { port: 22, label: "SSH" },
  { port: 80, label: "HTTP" },
  { port: 443, label: "HTTPS" },
  { port: 3000, label: "Dev" },
  { port: 5432, label: "Postgres" },
  { port: 6379, label: "Redis" },
  { port: 8006, label: "Proxmox" },
  { port: 8080, label: "Alt HTTP" },
  { port: 8090, label: "Keycloak" },
  { port: 9090, label: "Monitoring" },
  { port: 9999, label: "SonarQube" },
];

const CRITICAL_PORTS = [5432, 6379, 8006];

const ROLE_OPTIONS = [
  { value: "viewer", label: "Viewer — read-only web access" },
  { value: "developer", label: "Developer — SSH + web access" },
  { value: "maintainer", label: "Maintainer — deploy + manage" },
  { value: "admin", label: "Admin — full access (use sparingly)" },
];

// ─── Conflict Detection ───

function detectRuleConflicts(existingRules, newRule, nodes, containers) {
  const warnings = [];

  const hasAllAccess = existingRules.some((r) => r.type === "all");
  if (hasAllAccess) {
    warnings.push("User already has ALL RESOURCES access — individual rules are redundant.");
    return warnings;
  }

  if (newRule.type === "all" && existingRules.length > 0) {
    warnings.push("Granting ALL RESOURCES will make existing individual rules redundant.");
  }

  if (newRule.type === "lxc") {
    // Check node-level overlap
    const container = containers.find((c) => c.id === newRule.target);
    if (container) {
      const nodeRule = existingRules.find(
        (r) => r.type === "node" && r.target === container.node
      );
      if (nodeRule) {
        const overlappingPorts = newRule.ports.filter((p) => nodeRule.ports.includes(p));
        if (overlappingPorts.length > 0) {
          const nodeName = nodes.find((n) => n.id === container.node)?.name || container.node;
          warnings.push(
            `Node-level rule for "${nodeName}" already covers ${container.name} on ports [${overlappingPorts.join(", ")}].`
          );
        }
      }
    }

    // Check direct duplicate
    const duplicate = existingRules.find(
      (r) => r.type === "lxc" && r.target === newRule.target
    );
    if (duplicate) {
      const overlapping = newRule.ports.filter((p) => duplicate.ports.includes(p));
      if (overlapping.length > 0) {
        warnings.push(
          `Duplicate: user already has access to this target on ports [${overlapping.join(", ")}].`
        );
      }
    }
  }

  if (newRule.type === "node") {
    // Check if individual container rules exist for containers on this node
    const nodeContainers = containers.filter((c) => c.node === newRule.target);
    nodeContainers.forEach((ct) => {
      const ctRule = existingRules.find(
        (r) => r.type === "lxc" && r.target === ct.id
      );
      if (ctRule) {
        warnings.push(
          `Container "${ct.name}" already has individual rules — node-level rule will overlap.`
        );
      }
    });
  }

  return warnings;
}

// ─── Icons ───

function Icon({ name, size = 16 }) {
  const props = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round",
    strokeLinejoin: "round",
  };

  switch (name) {
    case "shield":
      return <svg {...props}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>;
    case "server":
      return <svg {...props}><rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" /><circle cx="6" cy="6" r="1" fill="currentColor" /><circle cx="6" cy="18" r="1" fill="currentColor" /></svg>;
    case "box":
      return <svg {...props}><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z" /><polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" /></svg>;
    case "user":
      return <svg {...props}><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>;
    case "plus":
      return <svg {...props} width={15} height={15} strokeWidth={2.5}><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>;
    case "trash":
      return <svg {...props} width={14} height={14}><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" /></svg>;
    case "copy":
      return <svg {...props} width={14} height={14}><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" /></svg>;
    case "check":
      return <svg {...props} width={14} height={14} strokeWidth={2.5}><polyline points="20 6 9 17 4 12" /></svg>;
    case "alert":
      return <svg {...props} width={15} height={15}><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>;
    case "close":
      return <svg {...props}><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>;
    case "ban":
      return <svg {...props} width={14} height={14}><circle cx="12" cy="12" r="10" /><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" /></svg>;
    case "clock":
      return <svg {...props} width={14} height={14}><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>;
    case "key":
      return <svg {...props} width={14} height={14}><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" /></svg>;
    case "chevronDown":
      return <svg {...props} width={12} height={12} strokeWidth={2.5}><polyline points="6 9 12 15 18 9" /></svg>;
    case "download":
      return <svg {...props} width={14} height={14}><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>;
    case "lock":
      return <svg {...props} width={14} height={14}><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" /></svg>;
    case "unlock":
      return <svg {...props} width={14} height={14}><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 019.9-1" /></svg>;
    case "zap":
      return <svg {...props} width={14} height={14}><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" /></svg>;
    case "diff":
      return <svg {...props} width={14} height={14}><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /><line x1="5" y1="18" x2="19" y2="18" /></svg>;
    default:
      return null;
  }
}

// ─── Initial State ───

const INITIAL_STATE = {
  nodes: [
    { id: "pve", name: "pve", ip: "10.0.0.27", status: "online" },
    { id: "proxmox2", name: "proxmox2", ip: "10.0.0.72", status: "online" },
    { id: "proxmox", name: "proxmox", ip: "10.0.0.28", status: "online" },
    { id: "node4", name: "node-4 (planned)", ip: "—", status: "planned" },
  ],

  containers: [
    { id: "ct1001", name: "app-1",         ip: "10.0.0.96",  node: "pve",      vmid: 1001, critical: false, kind: "ct" },
    { id: "ct1003", name: "app-2",      ip: "—",             node: "pve",      vmid: 1003, critical: false, kind: "ct" },
    { id: "ct1005", name: "app-3-dev",        ip: "10.0.0.94",  node: "pve",      vmid: 1005, critical: false, kind: "ct" },
    { id: "ct3001", name: "keycloak",       ip: "10.0.0.30",  node: "pve",      vmid: 3001, critical: true,  kind: "ct" },
    { id: "ct3002", name: "web-app",     ip: "—",             node: "pve",      vmid: 3002, critical: false, kind: "ct" },
    { id: "ct3005", name: "nginx",          ip: "—",             node: "pve",      vmid: 3005, critical: true,  kind: "ct" },
    { id: "ct4000", name: "portal",      ip: "—",             node: "pve",      vmid: 4000, critical: false, kind: "ct" },
    { id: "ct6000", name: "backend-1",       ip: "—",             node: "pve",      vmid: 6000, critical: false, kind: "ct" },
    { id: "ct105",  name: "tailscale-exit", ip: "10.0.0.155", node: "proxmox2", vmid: 105,  critical: true,  kind: "ct" },
    { id: "ct2000", name: "property",       ip: "—",             node: "proxmox2", vmid: 2000, critical: false, kind: "ct" },
    { id: "ct5000", name: "jenkins",        ip: "10.0.0.97",  node: "proxmox2", vmid: 5000, critical: true,  kind: "ct" },
    { id: "ct5001", name: "jenkins-agent",  ip: "—",             node: "proxmox2", vmid: 5001, critical: false, kind: "ct" },
    { id: "vm500",  name: "k3s-1",          ip: "10.0.0.101", node: "proxmox2", vmid: 500,  critical: false, kind: "vm" },
    { id: "ct9000", name: "ubuntu-test",    ip: "—",             node: "proxmox2", vmid: 9000, critical: false, kind: "ct" },
    { id: "ct1002", name: "sonarqube",      ip: "10.0.0.98",  node: "proxmox",  vmid: 1002, critical: false, kind: "ct" },
    { id: "ct1004", name: "app-3",            ip: "10.0.0.172", node: "proxmox",  vmid: 1004, critical: false, kind: "ct" },
  ],

  users: [
    {
      id: "u0",
      name: "Admin (You)",
      email: "admin@example.com",
      role: "admin",
      status: "active",
      created: "2025-01-15",
      expires: null,
      rules: [{ target: "*", ports: [22, 80, 443, 3000, 5432, 6379, 8006, 8080], type: "all" }],
    },
    {
      id: "u1",
      name: "Mike",
      email: "mike@example.com",
      role: "developer",
      status: "active",
      created: "2026-02-10",
      expires: "2026-06-10",
      rules: [
        { target: "ct9000", ports: [22, 80, 443, 3000], type: "lxc" },
        { target: "ct2000", ports: [22, 80], type: "lxc" },
      ],
    },
    {
      id: "u2",
      name: "Sara",
      email: "sara@example.com",
      role: "viewer",
      status: "suspended",
      created: "2026-01-20",
      expires: "2026-04-01",
      rules: [{ target: "ct3002", ports: [80, 443], type: "lxc" }],
    },
  ],

  modal: null,
  toast: null,

  auditLog: [
    { timestamp: "2026-03-21T09:12:00Z", action: "User mike@example.com granted SSH+HTTP to ubuntu-test (CT 9000)", severity: "info" },
    { timestamp: "2026-03-20T14:30:00Z", action: "User sara@example.com suspended — all access revoked", severity: "warn" },
    { timestamp: "2026-03-19T11:00:00Z", action: "ACL policy exported and applied to Tailscale", severity: "info" },
    { timestamp: "2026-03-18T08:45:00Z", action: "Attempted access to keycloak (CT 3001) by sara@example.com — BLOCKED", severity: "error" },
  ],

  // Security state
  lockdownActive: false,
  lastPushedACL: null,
  sessionActive: true,
  lastActivity: Date.now(),
  pushHistory: [], // timestamps of recent pushes
};

// ─── Reducer Helpers ───

function createAuditEntry(action, severity = "info") {
  return { timestamp: new Date().toISOString(), action, severity };
}

function countActiveAdmins(users) {
  return users.filter((u) => u.role === "admin" && u.status === "active").length;
}

function isUserExpired(user) {
  return user.expires && new Date(user.expires) < new Date();
}

// ─── Reducer ───

function reducer(state, action) {
  // Block mutations during session timeout (except session/toast actions)
  if (
    !state.sessionActive &&
    !["SESSION_RESUME", "CLEAR_TOAST"].includes(action.type)
  ) {
    return state;
  }

  // Block most mutations during lockdown
  if (
    state.lockdownActive &&
    ["ADD_USER", "ADD_RULE", "TOGGLE_STATUS"].includes(action.type)
  ) {
    // Allow suspending (not reactivating) during lockdown
    if (action.type === "TOGGLE_STATUS") {
      const user = state.users.find((u) => u.id === action.id);
      if (user?.status === "suspended") {
        return {
          ...state,
          toast: { message: "Cannot reactivate users during lockdown", kind: "error" },
        };
      }
    } else {
      return {
        ...state,
        toast: { message: "Action blocked — lockdown is active", kind: "error" },
      };
    }
  }

  switch (action.type) {
    case "ADD_USER": {
      const { name, email, role, expires } = action.payload;

      // Defense-in-depth: validate email
      if (!isValidEmail(email)) {
        return { ...state, toast: { message: "Invalid email address", kind: "error" } };
      }

      // Duplicate check
      if (state.users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
        return { ...state, toast: { message: "User with this email already exists", kind: "error" } };
      }

      // Name validation
      if (!isValidName(name)) {
        return { ...state, toast: { message: "Invalid name (2-64 chars, no special characters)", kind: "error" } };
      }

      // Expiry validation
      if (expires && new Date(expires) <= new Date()) {
        return { ...state, toast: { message: "Expiry date must be in the future", kind: "error" } };
      }

      const newUser = {
        id: `u${Date.now()}`,
        name: sanitizeName(name),
        email: email.trim(),
        role,
        expires: expires || null,
        status: "active",
        created: new Date().toISOString().slice(0, 10),
        rules: [],
      };
      return {
        ...state,
        users: [...state.users, newUser],
        modal: null,
        toast: { message: `Added ${newUser.name}`, kind: "ok" },
        auditLog: [
          createAuditEntry(`User ${email} added as ${role}`),
          ...state.auditLog,
        ],
      };
    }

    case "DELETE_USER": {
      const user = state.users.find((u) => u.id === action.id);
      if (!user) return state;

      // Prevent deleting last admin
      if (user.role === "admin" && countActiveAdmins(state.users) <= 1) {
        return {
          ...state,
          modal: null,
          toast: { message: "Cannot remove the last admin — would lock out all access", kind: "error" },
        };
      }

      return {
        ...state,
        users: state.users.filter((u) => u.id !== action.id),
        modal: null,
        toast: { message: "User removed", kind: "ok" },
        auditLog: [
          createAuditEntry(`User ${user.email} removed permanently`, "error"),
          ...state.auditLog,
        ],
      };
    }

    case "TOGGLE_STATUS": {
      const user = state.users.find((u) => u.id === action.id);
      if (!user) return state;

      const nextStatus = user.status === "active" ? "suspended" : "active";

      // Prevent suspending last admin
      if (nextStatus === "suspended" && user.role === "admin" && countActiveAdmins(state.users) <= 1) {
        return {
          ...state,
          toast: { message: "Cannot suspend the last admin — would lock out all access", kind: "error" },
        };
      }

      const severity = nextStatus === "suspended" ? "warn" : "warn"; // reactivation is also warn-level

      return {
        ...state,
        users: state.users.map((u) =>
          u.id === action.id ? { ...u, status: nextStatus } : u
        ),
        toast: {
          message: nextStatus === "suspended" ? "User suspended" : "User reactivated",
          kind: nextStatus === "suspended" ? "warn" : "ok",
        },
        auditLog: [
          createAuditEntry(`User ${user.email} ${nextStatus}`, severity),
          ...state.auditLog,
        ],
      };
    }

    case "ADD_RULE": {
      const { userId, rule } = action.payload;
      const user = state.users.find((u) => u.id === userId);
      if (!user) return state;

      // Block rules for expired users
      if (isUserExpired(user)) {
        return {
          ...state,
          modal: null,
          toast: { message: "Cannot add rules to expired user — extend expiry first", kind: "error" },
        };
      }

      // Block forbidden ports
      const forbiddenFound = rule.ports.filter((p) => FORBIDDEN_PORTS.includes(p));
      if (forbiddenFound.length > 0) {
        return {
          ...state,
          toast: { message: `Port ${forbiddenFound[0]} is reserved and cannot be granted`, kind: "error" },
        };
      }

      const targetName =
        rule.type === "node"
          ? state.nodes.find((n) => n.id === rule.target)?.name
          : rule.type === "lxc"
            ? state.containers.find((c) => c.id === rule.target)?.name
            : "all resources";

      // Determine audit severity
      const isCriticalTarget =
        rule.type === "lxc" && state.containers.find((c) => c.id === rule.target)?.critical;
      const isProtectedTarget = PROTECTED_CONTAINERS.includes(rule.target);
      const hasCriticalPort = rule.ports.some((p) => CRITICAL_PORTS.includes(p));
      const isAllAccess = rule.type === "all";

      let severity = "info";
      if (hasCriticalPort || isCriticalTarget) severity = "warn";
      if (isAllAccess || isProtectedTarget) severity = "error";

      return {
        ...state,
        users: state.users.map((u) =>
          u.id === userId ? { ...u, rules: [...u.rules, rule] } : u
        ),
        modal: null,
        toast: { message: "Access rule added", kind: "ok" },
        auditLog: [
          createAuditEntry(
            `Rule added for ${user.email}: ${targetName} ports [${rule.ports}]${isProtectedTarget ? " ⚠ PROTECTED CONTAINER" : ""}`,
            severity
          ),
          ...state.auditLog,
        ],
      };
    }

    case "DELETE_RULE": {
      const user = state.users.find((u) => u.id === action.userId);
      const rule = user?.rules[action.ruleIndex];
      const targetName = rule
        ? rule.type === "all"
          ? "all resources"
          : rule.type === "node"
            ? state.nodes.find((n) => n.id === rule.target)?.name || rule.target
            : state.containers.find((c) => c.id === rule.target)?.name || rule.target
        : "unknown";

      return {
        ...state,
        users: state.users.map((u) =>
          u.id === action.userId
            ? { ...u, rules: u.rules.filter((_, index) => index !== action.ruleIndex) }
            : u
        ),
        toast: { message: "Rule removed", kind: "ok" },
        auditLog: [
          createAuditEntry(
            `Rule removed for ${user?.email}: ${targetName} ports [${rule?.ports || "?"}]`,
            "warn"
          ),
          ...state.auditLog,
        ],
      };
    }

    case "SET_IP": {
      // Validate IP
      if (action.ip !== "—" && !isValidIPv4(action.ip)) {
        return { ...state, toast: { message: "Invalid IP address format", kind: "error" } };
      }
      if (action.ip !== "—" && isReservedIP(action.ip)) {
        return { ...state, toast: { message: "Reserved IP address — cannot use", kind: "error" } };
      }

      if (action.kind === "node") {
        return {
          ...state,
          nodes: state.nodes.map((n) =>
            n.id === action.id ? { ...n, ip: action.ip } : n
          ),
        };
      }
      return {
        ...state,
        containers: state.containers.map((c) =>
          c.id === action.id ? { ...c, ip: action.ip } : c
        ),
      };
    }

    case "SET_MODAL":
      return { ...state, modal: action.payload };

    case "CLEAR_TOAST":
      return { ...state, toast: null };

    // ─── Emergency Lockdown ───

    case "EMERGENCY_LOCKDOWN": {
      const suspendedUsers = state.users
        .filter((u) => u.role !== "admin" && u.status === "active")
        .map((u) => u.email);

      return {
        ...state,
        lockdownActive: true,
        users: state.users.map((u) =>
          u.role !== "admin" ? { ...u, status: "suspended" } : u
        ),
        modal: null,
        toast: { message: "EMERGENCY LOCKDOWN ACTIVATED", kind: "error" },
        auditLog: [
          createAuditEntry(
            `EMERGENCY LOCKDOWN: All non-admin access revoked. Affected: [${suspendedUsers.join(", ")}]`,
            "error"
          ),
          ...state.auditLog,
        ],
      };
    }

    case "EMERGENCY_LIFT": {
      return {
        ...state,
        lockdownActive: false,
        modal: null,
        toast: { message: "Lockdown lifted — reactivate users manually", kind: "warn" },
        auditLog: [
          createAuditEntry("LOCKDOWN LIFTED by admin. Users remain suspended until manually reactivated.", "warn"),
          ...state.auditLog,
        ],
      };
    }

    // ─── ACL Push Tracking ───

    case "MARK_ACL_PUSHED": {
      const now = Date.now();
      return {
        ...state,
        lastPushedACL: action.aclJson,
        pushHistory: [...state.pushHistory, now],
        modal: null,
        toast: { message: "ACL policy marked as pushed", kind: "ok" },
        auditLog: [
          createAuditEntry("ACL policy pushed to Tailscale", "warn"),
          ...state.auditLog,
        ],
      };
    }

    // ─── Session ───

    case "SESSION_TIMEOUT": {
      return {
        ...state,
        sessionActive: false,
        auditLog: [
          createAuditEntry("Session timed out due to inactivity", "warn"),
          ...state.auditLog,
        ],
      };
    }

    case "SESSION_RESUME": {
      return {
        ...state,
        sessionActive: true,
        lastActivity: Date.now(),
        auditLog: [
          createAuditEntry("Session resumed after re-authentication", "info"),
          ...state.auditLog,
        ],
      };
    }

    case "ACTIVITY_PING": {
      return { ...state, lastActivity: Date.now() };
    }

    // ─── Expiry Check ───

    case "CHECK_EXPIRY": {
      const newlyExpired = state.users.filter(
        (u) => u.status === "active" && isUserExpired(u)
      );
      if (newlyExpired.length === 0) return state;

      return {
        ...state,
        auditLog: [
          ...newlyExpired.map((u) =>
            createAuditEntry(`User ${u.email} access expired — rules inactive`, "warn")
          ),
          ...state.auditLog,
        ],
      };
    }

    default:
      return state;
  }
}

// ─── ACL Generator (Security-Hardened) ───

function generateACL(users, nodes, containers) {
  const acls = [];
  const skipped = [];
  const tagOwners = {
    "tag:admin": [],
    "tag:maintainer": [],
    "tag:developer": [],
    "tag:viewer": [],
  };

  const activeUsers = users.filter(
    (user) => user.status === "active" && !isUserExpired(user)
  );

  activeUsers.forEach((user) => {
    const tagKey = `tag:${user.role}`;
    if (tagOwners[tagKey] && !tagOwners[tagKey].includes(user.email)) {
      tagOwners[tagKey].push(user.email);
    }

    user.rules.forEach((rule) => {
      if (rule.type === "all") {
        acls.push({
          action: "accept",
          src: [user.email],
          dst: ["10.0.0.0/24:*"],
          comment: `${user.name} — full access`,
        });
        return;
      }

      if (rule.type === "node") {
        const node = nodes.find((n) => n.id === rule.target);
        if (!node) return;

        if (node.ip === "—") {
          skipped.push(`${node.name} (no IP)`);
          return;
        }

        const nodeContainers = containers.filter((c) => c.node === rule.target);
        const validContainers = nodeContainers.filter((c) => c.ip !== "—");
        const skippedContainers = nodeContainers.filter((c) => c.ip === "—");

        skippedContainers.forEach((c) => skipped.push(`${c.name} (no IP)`));

        const allIPs = [node.ip, ...validContainers.map((c) => c.ip)];
        rule.ports.forEach((port) => {
          allIPs.forEach((ip) => {
            acls.push({
              action: "accept",
              src: [user.email],
              dst: [`${ip}:${port}`],
              comment: `${user.name} → ${node.name}`,
            });
          });
        });
        return;
      }

      if (rule.type === "lxc") {
        const container = containers.find((c) => c.id === rule.target);
        if (!container) return;

        if (container.ip === "—") {
          skipped.push(`${container.name} (no IP)`);
          return;
        }

        rule.ports.forEach((port) => {
          acls.push({
            action: "accept",
            src: [user.email],
            dst: [`${container.ip}:${port}`],
            comment: `${user.name} → ${container.name}`,
          });
        });
      }
    });
  });

  // Merge rules with same source and comment
  const merged = [];
  acls.forEach((acl) => {
    const existing = merged.find(
      (m) => m.src[0] === acl.src[0] && m.comment === acl.comment
    );
    if (existing) {
      acl.dst.forEach((dst) => {
        if (!existing.dst.includes(dst)) existing.dst.push(dst);
      });
    } else {
      merged.push({ ...acl });
    }
  });

  const result = JSON.stringify({ acls: merged, tagOwners }, null, 2);
  return { json: result, skippedCount: skipped.length, skippedNames: skipped };
}

// ─── Simple Diff ───

function computeACLDiff(oldACL, newACL) {
  if (!oldACL) return null;
  const oldLines = oldACL.split("\n");
  const newLines = newACL.split("\n");

  const added = [];
  const removed = [];

  const oldSet = new Set(oldLines);
  const newSet = new Set(newLines);

  newLines.forEach((line, i) => {
    if (!oldSet.has(line)) added.push({ line, num: i + 1 });
  });

  oldLines.forEach((line, i) => {
    if (!newSet.has(line)) removed.push({ line, num: i + 1 });
  });

  return { added, removed, hasChanges: added.length > 0 || removed.length > 0 };
}

// ─── Shared Styles ───

const styles = {
  input: {
    width: "100%",
    padding: "8px 12px",
    border: `1px solid ${THEME.colors.borderInput}`,
    borderRadius: THEME.radii.md,
    fontSize: 14,
    fontFamily: "inherit",
    background: THEME.colors.surface,
    color: THEME.colors.text,
    outline: "none",
    boxSizing: "border-box",
  },
  inputError: {
    borderColor: THEME.colors.danger,
  },
  iconButton: {
    background: "none",
    border: "none",
    cursor: "pointer",
    padding: 4,
  },
  errorText: {
    fontSize: 11,
    color: THEME.colors.danger,
    marginTop: 4,
  },
};

// ─── Primitive Components ───

function Badge({ children, color = "#64748b", bg = "#f1f5f9" }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: 11,
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: ".06em",
        color,
        background: bg,
        padding: "3px 8px",
        borderRadius: THEME.radii.sm,
      }}
    >
      {children}
    </span>
  );
}

function StatusDot({ color }) {
  return (
    <svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true">
      <circle cx="4" cy="4" r="4" fill={color} />
    </svg>
  );
}

function Button({ children, onClick, variant = "default", size = "md", disabled, style: extraStyle }) {
  const baseStyle = {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    border: "none",
    cursor: disabled ? "not-allowed" : "pointer",
    fontWeight: 600,
    fontFamily: "inherit",
    transition: "all .15s",
    opacity: disabled ? 0.5 : 1,
    borderRadius: THEME.radii.md,
  };

  const sizeStyle =
    size === "sm"
      ? { fontSize: 12, padding: "5px 10px" }
      : { fontSize: 13, padding: "8px 14px" };

  const variantStyles = {
    default: { background: THEME.colors.muted, color: "#3d3929" },
    primary: { background: THEME.colors.primary, color: THEME.colors.surface },
    danger: { background: THEME.colors.dangerBg, color: THEME.colors.dangerDark, border: `1px solid ${THEME.colors.dangerBorder}` },
    dangerSolid: { background: THEME.colors.danger, color: THEME.colors.surface },
    success: { background: THEME.colors.successBg, color: THEME.colors.successDark, border: `1px solid ${THEME.colors.successBorder}` },
    warning: { background: THEME.colors.warningBg, color: THEME.colors.warningDark, border: `1px solid ${THEME.colors.warningBorder}` },
  };

  return (
    <button
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      style={{ ...baseStyle, ...sizeStyle, ...(variantStyles[variant] || variantStyles.default), ...extraStyle }}
    >
      {children}
    </button>
  );
}

function Modal({ title, children, onClose, width = 520 }) {
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={title}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,.22)",
        backdropFilter: "blur(2px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: THEME.colors.surfaceAlt,
          borderRadius: THEME.radii.xxl,
          width,
          maxWidth: "95vw",
          maxHeight: "85vh",
          overflow: "auto",
          boxShadow: THEME.shadows.modal,
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "16px 20px",
            borderBottom: `1px solid ${THEME.colors.muted}`,
          }}
        >
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: THEME.colors.text }}>
            {title}
          </h3>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            style={{ ...styles.iconButton, color: THEME.colors.textFaint }}
          >
            <Icon name="close" />
          </button>
        </div>
        <div style={{ padding: 20 }}>{children}</div>
      </div>
    </div>
  );
}

function Field({ label, children, error }) {
  return (
    <label style={{ display: "block", marginBottom: 12 }}>
      <span
        style={{
          display: "block",
          fontSize: 12,
          fontWeight: 600,
          color: THEME.colors.textMuted,
          marginBottom: 4,
          textTransform: "uppercase",
          letterSpacing: ".04em",
        }}
      >
        {label}
      </span>
      {children}
      {error && <div style={styles.errorText}>{error}</div>}
    </label>
  );
}

function WarningBanner({ children, severity = "warning" }) {
  const isError = severity === "error";
  const bgColor = isError ? THEME.colors.dangerBg : THEME.colors.warningLight;
  const borderColor = isError ? "#fca5a5" : THEME.colors.warningBorder;
  const textColor = isError ? THEME.colors.dangerDeep : THEME.colors.warningDeep;
  const iconColor = isError ? THEME.colors.danger : THEME.colors.warning;

  return (
    <div
      role="alert"
      style={{
        background: bgColor,
        border: `1px solid ${borderColor}`,
        borderRadius: THEME.radii.lg,
        padding: "10px 14px",
        marginBottom: 12,
        display: "flex",
        gap: 8,
        alignItems: "flex-start",
      }}
    >
      <span style={{ color: iconColor, flexShrink: 0 }}><Icon name="alert" /></span>
      <span style={{ fontSize: 13, color: textColor }}>{children}</span>
    </div>
  );
}

// ─── Danger Confirm Modal (Type-to-Confirm) ───

function DangerConfirmModal({ title, message, confirmPhrase, confirmLabel, onConfirm, dispatch }) {
  const [typed, setTyped] = useState("");
  const isMatch = typed === confirmPhrase;

  return (
    <Modal title={title} onClose={() => dispatch({ type: "SET_MODAL", payload: null })} width={460}>
      <p style={{ fontSize: 14, color: THEME.colors.textSecondary, margin: "0 0 16px", lineHeight: 1.6 }}>
        {message}
      </p>
      <div
        style={{
          background: THEME.colors.dangerBg,
          border: `1px solid ${THEME.colors.dangerBorder}`,
          borderRadius: THEME.radii.lg,
          padding: "12px 14px",
          marginBottom: 16,
        }}
      >
        <div style={{ fontSize: 12, fontWeight: 600, color: THEME.colors.dangerDark, marginBottom: 8 }}>
          Type <code style={{ background: "#fff", padding: "2px 6px", borderRadius: 3, fontFamily: THEME.fonts.mono, fontWeight: 700 }}>{confirmPhrase}</code> to confirm
        </div>
        <input
          style={{
            ...styles.input,
            fontFamily: THEME.fonts.mono,
            fontWeight: 600,
            border: `2px solid ${isMatch ? THEME.colors.success : THEME.colors.dangerBorder}`,
          }}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={confirmPhrase}
          autoFocus
        />
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button onClick={() => dispatch({ type: "SET_MODAL", payload: null })}>Cancel</Button>
        <Button
          variant="dangerSolid"
          disabled={!isMatch}
          onClick={() => { onConfirm(); setTyped(""); }}
        >
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}

// ─── Confirm Modal (simple) ───

function ConfirmModal({ title, message, confirmLabel, onConfirm, dispatch }) {
  return (
    <Modal title={title} onClose={() => dispatch({ type: "SET_MODAL", payload: null })} width={420}>
      <p style={{ fontSize: 14, color: THEME.colors.textSecondary, margin: "0 0 20px", lineHeight: 1.6 }}>
        {message}
      </p>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Button onClick={() => dispatch({ type: "SET_MODAL", payload: null })}>Cancel</Button>
        <Button variant="danger" onClick={onConfirm}>{confirmLabel}</Button>
      </div>
    </Modal>
  );
}

// ─── Session Timeout Overlay ───

function SessionTimeoutOverlay({ dispatch }) {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,.65)",
        backdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 2000,
      }}
    >
      <div
        style={{
          background: THEME.colors.surface,
          borderRadius: THEME.radii.xxl,
          padding: "40px 48px",
          textAlign: "center",
          maxWidth: 400,
          boxShadow: THEME.shadows.modal,
        }}
      >
        <div
          style={{
            width: 56,
            height: 56,
            borderRadius: "50%",
            background: THEME.colors.warningBg,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto 16px",
            color: THEME.colors.warning,
          }}
        >
          <Icon name="lock" size={28} />
        </div>
        <h2 style={{ margin: "0 0 8px", fontSize: 20, fontWeight: 800, color: THEME.colors.text }}>
          Session Expired
        </h2>
        <p style={{ margin: "0 0 24px", fontSize: 14, color: THEME.colors.textMuted, lineHeight: 1.5 }}>
          Your session timed out after 15 minutes of inactivity. In production, this will redirect to Keycloak for re-authentication.
        </p>
        <Button
          variant="primary"
          onClick={() => dispatch({ type: "SESSION_RESUME" })}
          style={{ width: "100%", justifyContent: "center", padding: "12px 24px", fontSize: 14 }}
        >
          <Icon name="unlock" /> Re-authenticate
        </Button>
      </div>
    </div>
  );
}

// ─── Lockdown Banner ───

function LockdownBanner({ dispatch }) {
  return (
    <div
      role="alert"
      style={{
        background: THEME.colors.lockdownBg,
        color: "#fca5a5",
        padding: "12px 28px",
        display: "flex",
        alignItems: "center",
        gap: 10,
        fontSize: 13,
        fontWeight: 600,
      }}
    >
      <Icon name="zap" size={16} />
      <span style={{ flex: 1 }}>
        LOCKDOWN ACTIVE — Only admin access is permitted. All non-admin users have been suspended.
      </span>
      <Button
        size="sm"
        variant="warning"
        onClick={() =>
          dispatch({
            type: "SET_MODAL",
            payload: {
              type: "dangerConfirm",
              title: "Lift Emergency Lockdown?",
              message: "Users will remain suspended. You must manually reactivate each user after review.",
              confirmPhrase: "LIFT",
              confirmLabel: "Lift Lockdown",
              onConfirm: () => dispatch({ type: "EMERGENCY_LIFT" }),
            },
          })
        }
      >
        <Icon name="unlock" /> Lift Lockdown
      </Button>
    </div>
  );
}

// ─── Add User Modal ───

function AddUserModal({ dispatch }) {
  const [form, setForm] = useState({ name: "", email: "", role: "developer", expires: "" });
  const [touched, setTouched] = useState({});

  const updateField = (field, value) => setForm((prev) => ({ ...prev, [field]: value }));
  const touchField = (field) => setTouched((prev) => ({ ...prev, [field]: true }));

  const emailError = touched.email && form.email && !isValidEmail(form.email)
    ? "Enter a valid email — this becomes the Tailscale identity"
    : null;
  const nameError = touched.name && form.name && !isValidName(form.name)
    ? "2-64 characters, no < > { } \" ' ` \\ allowed"
    : null;

  const isValid =
    isValidName(form.name) &&
    isValidEmail(form.email) &&
    (!form.expires || new Date(form.expires) > new Date());

  const todayStr = new Date().toISOString().slice(0, 10);

  return (
    <Modal title="Add User" onClose={() => dispatch({ type: "SET_MODAL", payload: null })}>
      <Field label="Full Name" error={nameError}>
        <input
          style={{ ...styles.input, ...(nameError ? styles.inputError : {}) }}
          value={form.name}
          placeholder="Jane Doe"
          onChange={(e) => updateField("name", e.target.value)}
          onBlur={() => touchField("name")}
        />
      </Field>

      <Field label="Email (Tailscale identity)" error={emailError}>
        <input
          style={{ ...styles.input, ...(emailError ? styles.inputError : {}) }}
          value={form.email}
          placeholder="jane@example.com"
          onChange={(e) => updateField("email", e.target.value)}
          onBlur={() => touchField("email")}
        />
      </Field>

      <Field label="Role">
        <select
          style={styles.input}
          value={form.role}
          onChange={(e) => updateField("role", e.target.value)}
        >
          {ROLE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </Field>

      {form.role === "admin" && (
        <WarningBanner severity="error">
          Admin role grants full access to the entire network. Use sparingly.
        </WarningBanner>
      )}

      <Field label="Access Expires (optional)">
        <input
          style={styles.input}
          type="date"
          value={form.expires}
          min={todayStr}
          onChange={(e) => updateField("expires", e.target.value)}
        />
      </Field>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        <Button onClick={() => dispatch({ type: "SET_MODAL", payload: null })}>Cancel</Button>
        <Button
          variant="primary"
          disabled={!isValid}
          onClick={() =>
            dispatch({
              type: "ADD_USER",
              payload: {
                name: form.name,
                email: form.email,
                role: form.role,
                expires: form.expires || null,
              },
            })
          }
        >
          Add User
        </Button>
      </div>
    </Modal>
  );
}

// ─── Add Rule Modal ───

function AddRuleModal({ userId, dispatch, nodes, containers, users }) {
  const [scope, setScope] = useState("lxc");
  const [target, setTarget] = useState(containers[0]?.id || "");
  const [selectedPorts, setSelectedPorts] = useState([22, 80, 443]);
  const [customPort, setCustomPort] = useState("");

  const user = users.find((u) => u.id === userId);
  const targetList = scope === "node" ? nodes : containers;

  useEffect(() => {
    setTarget(targetList[0]?.id || "");
  }, [scope, targetList]);

  const togglePort = (port) =>
    setSelectedPorts((prev) =>
      prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port]
    );

  const addCustomPort = () => {
    const port = parseInt(customPort, 10);
    if (port >= 1 && port <= 65535 && !selectedPorts.includes(port)) {
      if (FORBIDDEN_PORTS.includes(port)) {
        return; // handled in UI
      }
      setSelectedPorts((prev) => [...prev, port]);
      setCustomPort("");
    }
  };

  const hasCriticalPort = selectedPorts.some((p) => CRITICAL_PORTS.includes(p));
  const hasForbiddenPort = selectedPorts.some((p) => FORBIDDEN_PORTS.includes(p));
  const isCriticalTarget = scope === "lxc" && containers.find((c) => c.id === target)?.critical;
  const isProtectedTarget = PROTECTED_CONTAINERS.includes(target);
  const isNonAdmin = user && user.role !== "admin";

  // Conflict detection
  const conflicts = user
    ? detectRuleConflicts(user.rules, { target, ports: selectedPorts, type: scope }, nodes, containers)
    : [];

  const customPortNum = parseInt(customPort, 10);
  const isCustomPortForbidden = FORBIDDEN_PORTS.includes(customPortNum);
  const isCustomPortValid = customPort === "" || (customPortNum >= 1 && customPortNum <= 65535);

  return (
    <Modal
      title="Add Access Rule"
      onClose={() => dispatch({ type: "SET_MODAL", payload: null })}
      width={560}
    >
      <Field label="Scope">
        <select style={styles.input} value={scope} onChange={(e) => setScope(e.target.value)}>
          <option value="lxc">Single Container / VM</option>
          <option value="node">Entire Node (all CTs on node)</option>
        </select>
      </Field>

      <Field label={scope === "node" ? "Node" : "Container / VM"}>
        <select style={styles.input} value={target} onChange={(e) => setTarget(e.target.value)}>
          {targetList.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name}
              {item.vmid ? ` (${item.vmid})` : ""} — {item.ip}
              {item.critical ? " ⚠ CRITICAL" : ""}
              {PROTECTED_CONTAINERS.includes(item.id) ? " 🔒 PROTECTED" : ""}
            </option>
          ))}
        </select>
      </Field>

      {isProtectedTarget && isNonAdmin && (
        <WarningBanner severity="error">
          This is the Tailscale subnet router. Granting access here exposes the entire network routing layer. Only admins should access this container.
        </WarningBanner>
      )}

      {isCriticalTarget && !isProtectedTarget && (
        <WarningBanner>
          Critical infrastructure container. Grant access carefully.
        </WarningBanner>
      )}

      <div style={{ marginBottom: 12 }}>
        <span
          style={{
            display: "block",
            fontSize: 12,
            fontWeight: 600,
            color: THEME.colors.textMuted,
            marginBottom: 8,
            textTransform: "uppercase",
            letterSpacing: ".04em",
          }}
        >
          Allowed Ports
        </span>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }} role="group" aria-label="Port selection">
          {PORT_DEFINITIONS.map((portDef) => {
            const isSelected = selectedPorts.includes(portDef.port);
            const isCritical = CRITICAL_PORTS.includes(portDef.port);
            return (
              <button
                key={portDef.port}
                onClick={() => togglePort(portDef.port)}
                aria-pressed={isSelected}
                style={{
                  padding: "6px 12px",
                  borderRadius: THEME.radii.md,
                  fontSize: 12,
                  fontWeight: 600,
                  fontFamily: "inherit",
                  cursor: "pointer",
                  transition: "all .15s",
                  border: isSelected
                    ? `2px solid ${isCritical ? THEME.colors.danger : THEME.colors.primary}`
                    : `1px solid ${THEME.colors.borderInput}`,
                  background: isSelected
                    ? isCritical ? THEME.colors.dangerBg : THEME.colors.primaryBg
                    : THEME.colors.surface,
                  color: isSelected
                    ? isCritical ? THEME.colors.dangerDark : "#1d4ed8"
                    : THEME.colors.textMuted,
                }}
              >
                {portDef.port}{" "}
                <span style={{ fontWeight: 400, opacity: 0.7 }}>{portDef.label}</span>
                {isCritical && <span style={{ marginLeft: 4, fontSize: 10 }}>⚠</span>}
              </button>
            );
          })}
        </div>

        {/* Custom port input */}
        <div style={{ display: "flex", gap: 6, marginTop: 8, alignItems: "center" }}>
          <input
            style={{ ...styles.input, width: 100, ...(isCustomPortForbidden ? styles.inputError : {}) }}
            type="number"
            min="1"
            max="65535"
            placeholder="Custom"
            value={customPort}
            onChange={(e) => setCustomPort(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addCustomPort()}
          />
          <Button
            size="sm"
            disabled={!customPort || !isCustomPortValid || isCustomPortForbidden}
            onClick={addCustomPort}
          >
            <Icon name="plus" /> Add Port
          </Button>
          {isCustomPortForbidden && (
            <span style={styles.errorText}>Port {customPortNum} is reserved</span>
          )}
        </div>
      </div>

      {hasForbiddenPort && (
        <WarningBanner severity="error">
          Port 3100 is reserved for the Access Manager and cannot be granted.
        </WarningBanner>
      )}

      {hasCriticalPort && !hasForbiddenPort && (
        <WarningBanner severity="error">
          Granting critical ports (database/management). High risk for non-admins.
        </WarningBanner>
      )}

      {conflicts.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          {conflicts.map((warning, i) => (
            <WarningBanner key={i}>{warning}</WarningBanner>
          ))}
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        <Button onClick={() => dispatch({ type: "SET_MODAL", payload: null })}>Cancel</Button>
        <Button
          variant={hasCriticalPort || isProtectedTarget ? "warning" : "primary"}
          disabled={!selectedPorts.length || hasForbiddenPort}
          onClick={() =>
            dispatch({
              type: "ADD_RULE",
              payload: { userId, rule: { target, ports: selectedPorts, type: scope } },
            })
          }
        >
          {isProtectedTarget
            ? "Grant (Protected Target)"
            : hasCriticalPort
              ? "Grant (High Risk)"
              : "Grant Access"}
        </Button>
      </div>
    </Modal>
  );
}

// ─── ACL Preview Modal (with Diff + Push) ───

function ACLPreviewModal({ users, nodes, containers, lastPushedACL, pushHistory, dispatch }) {
  const [copied, setCopied] = useState(false);
  const [showDiff, setShowDiff] = useState(false);

  const { json: aclJson, skippedCount, skippedNames } = generateACL(users, nodes, containers);
  const diff = computeACLDiff(lastPushedACL, aclJson);
  const hasUnpushedChanges = diff?.hasChanges ?? (lastPushedACL !== aclJson);

  // Rate limiting
  const now = Date.now();
  const recentPushes = pushHistory.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  const isRateLimited = recentPushes.length >= RATE_LIMIT_MAX_PUSHES;
  const cooldownRemaining = isRateLimited
    ? Math.ceil((recentPushes[0] + RATE_LIMIT_WINDOW_MS - now) / 1000)
    : 0;

  const handleCopy = useCallback(() => {
    if (skippedCount > 0) return; // Don't copy incomplete ACL
    navigator.clipboard?.writeText(aclJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [aclJson, skippedCount]);

  return (
    <Modal
      title="Generated Tailscale ACL Policy"
      onClose={() => dispatch({ type: "SET_MODAL", payload: null })}
      width={680}
    >
      <p style={{ fontSize: 13, color: THEME.colors.textMuted, margin: "0 0 12px" }}>
        Review the generated ACL before copying or pushing to Tailscale.
      </p>

      {skippedCount > 0 && (
        <WarningBanner severity="error">
          {skippedCount} rule{skippedCount !== 1 ? "s" : ""} skipped due to missing IPs: {skippedNames.join(", ")}.
          Set real IPs in the Infrastructure tab first. Copy and Push are disabled.
        </WarningBanner>
      )}

      {lastPushedACL && hasUnpushedChanges && (
        <div
          style={{
            background: THEME.colors.primaryBg,
            border: `1px solid ${THEME.colors.primary}`,
            borderRadius: THEME.radii.lg,
            padding: "10px 14px",
            marginBottom: 12,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Icon name="diff" />
          <span style={{ fontSize: 13, color: THEME.colors.primary, flex: 1 }}>
            ACL has changed since last push
            {diff && ` (+${diff.added.length} / -${diff.removed.length} lines)`}
          </span>
          <Button size="sm" onClick={() => setShowDiff(!showDiff)}>
            {showDiff ? "Hide Diff" : "Show Diff"}
          </Button>
        </div>
      )}

      {showDiff && diff && (
        <div
          style={{
            background: "#1e1b16",
            borderRadius: THEME.radii.lg,
            padding: 12,
            marginBottom: 12,
            maxHeight: 200,
            overflow: "auto",
            fontFamily: THEME.fonts.mono,
            fontSize: 11,
            lineHeight: 1.6,
          }}
        >
          {diff.removed.map((r, i) => (
            <div key={`r-${i}`} style={{ color: "#fca5a5" }}>- {r.line}</div>
          ))}
          {diff.added.map((a, i) => (
            <div key={`a-${i}`} style={{ color: "#86efac" }}>+ {a.line}</div>
          ))}
          {!diff.hasChanges && (
            <div style={{ color: THEME.colors.textFaint }}>No changes detected.</div>
          )}
        </div>
      )}

      <div style={{ position: "relative" }}>
        <pre
          style={{
            background: THEME.colors.surface,
            border: `1px solid ${THEME.colors.borderInput}`,
            borderRadius: THEME.radii.lg,
            padding: 16,
            fontSize: 12,
            lineHeight: 1.6,
            overflow: "auto",
            maxHeight: 400,
            color: THEME.colors.text,
            fontFamily: THEME.fonts.mono,
          }}
        >
          {aclJson}
        </pre>
        <button
          onClick={handleCopy}
          disabled={skippedCount > 0}
          aria-label={copied ? "Copied" : "Copy ACL to clipboard"}
          style={{
            position: "absolute",
            top: 8,
            right: 8,
            background: copied ? "#dcfce7" : "#f5f3ef",
            border: `1px solid ${THEME.colors.borderInput}`,
            borderRadius: THEME.radii.md,
            padding: "4px 10px",
            fontSize: 12,
            cursor: skippedCount > 0 ? "not-allowed" : "pointer",
            display: "flex",
            alignItems: "center",
            gap: 4,
            fontWeight: 600,
            color: copied ? THEME.colors.successDark : THEME.colors.textMuted,
            fontFamily: "inherit",
            opacity: skippedCount > 0 ? 0.4 : 1,
          }}
        >
          {copied ? <><Icon name="check" /> Copied</> : <><Icon name="copy" /> Copy</>}
        </button>
      </div>

      {isRateLimited && (
        <div style={{ marginTop: 12 }}>
          <WarningBanner>
            Rate limited — wait {cooldownRemaining}s before next push ({RATE_LIMIT_MAX_PUSHES} pushes max per 5 minutes).
          </WarningBanner>
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16, alignItems: "center" }}>
        {pushHistory.length > 0 && (
          <span style={{ fontSize: 11, color: THEME.colors.textFaint, marginRight: "auto" }}>
            Pushes this session: {pushHistory.length}
          </span>
        )}
        <Button onClick={() => dispatch({ type: "SET_MODAL", payload: null })}>Close</Button>
        <Button
          variant="primary"
          disabled={skippedCount > 0 || isRateLimited}
          onClick={() =>
            dispatch({
              type: "SET_MODAL",
              payload: {
                type: "dangerConfirm",
                title: "Push ACL to Tailscale?",
                message: `This will overwrite the current Tailscale ACL policy for your entire tailnet. ${users.filter(u => u.status === "active").length} active user(s) will be affected.`,
                confirmPhrase: "PUSH ACL",
                confirmLabel: "Push to Tailscale",
                onConfirm: () => dispatch({ type: "MARK_ACL_PUSHED", aclJson }),
              },
            })
          }
        >
          <Icon name="zap" /> Push to Tailscale
        </Button>
      </div>
    </Modal>
  );
}

// ─── Rule Tag ───

function RuleTag({ rule, onRemove, nodes, containers }) {
  const getTargetName = () => {
    if (rule.type === "all") return "ALL RESOURCES";
    if (rule.type === "node") return nodes.find((n) => n.id === rule.target)?.name || rule.target;
    return containers.find((c) => c.id === rule.target)?.name || rule.target;
  };

  const getTargetIP = () => {
    if (rule.type === "all") return "10.0.0.0/24";
    if (rule.type === "node") return nodes.find((n) => n.id === rule.target)?.ip || "";
    return containers.find((c) => c.id === rule.target)?.ip || "";
  };

  const isCriticalTarget = rule.type === "lxc" && containers.find((c) => c.id === rule.target)?.critical;
  const isProtected = PROTECTED_CONTAINERS.includes(rule.target);
  const hasCriticalPort = rule.ports.some((p) => CRITICAL_PORTS.includes(p));
  const isHighlighted = isCriticalTarget || hasCriticalPort || isProtected;

  const iconName = rule.type === "node" ? "server" : rule.type === "all" ? "shield" : "box";
  const iconColor =
    rule.type === "node"
      ? THEME.colors.purple
      : rule.type === "all"
        ? THEME.colors.dangerDark
        : THEME.colors.primary;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "8px 12px",
        background: isProtected ? THEME.colors.dangerBg : isHighlighted ? THEME.colors.warningBg : THEME.colors.surface,
        border: `1px solid ${isProtected ? THEME.colors.dangerBorder : isHighlighted ? THEME.colors.warningBorder : THEME.colors.border}`,
        borderRadius: THEME.radii.lg,
        fontSize: 13,
      }}
    >
      <span style={{ color: iconColor }}>
        <Icon name={iconName} />
      </span>

      <div style={{ flex: 1 }}>
        <span style={{ fontWeight: 600, color: THEME.colors.text }}>
          {getTargetName()}
          {isProtected && <span style={{ fontSize: 10, color: THEME.colors.danger, marginLeft: 6 }}>🔒 PROTECTED</span>}
        </span>
        <span
          style={{
            color: THEME.colors.textFaint,
            marginLeft: 6,
            fontSize: 12,
            fontFamily: THEME.fonts.mono,
          }}
        >
          {getTargetIP()}
        </span>
        <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
          {rule.ports.map((port) => (
            <span
              key={port}
              style={{
                fontSize: 10,
                fontWeight: 700,
                padding: "1px 6px",
                borderRadius: 3,
                background: CRITICAL_PORTS.includes(port) ? THEME.colors.dangerBg : "#f1f5f9",
                color: CRITICAL_PORTS.includes(port) ? THEME.colors.danger : "#64748b",
              }}
            >
              {port}
            </span>
          ))}
        </div>
      </div>

      {onRemove && (
        <button
          onClick={onRemove}
          aria-label="Remove rule"
          style={{ ...styles.iconButton, color: "#d1d5db" }}
        >
          <Icon name="close" />
        </button>
      )}
    </div>
  );
}

// ─── User Card ───

function UserCard({ user, dispatch, nodes, containers, users }) {
  const [isExpanded, setIsExpanded] = useState(false);

  const isLastAdmin =
    user.role === "admin" &&
    countActiveAdmins(users) <= 1 &&
    user.status === "active";

  const isExpired = isUserExpired(user);

  const statusColor =
    user.status === "active"
      ? isExpired ? THEME.colors.warning : THEME.colors.success
      : THEME.colors.danger;

  const statusLabel =
    user.status === "active"
      ? isExpired ? "EXPIRED" : "ACTIVE"
      : "SUSPENDED";

  const statusBg =
    user.status === "active"
      ? isExpired ? THEME.colors.warningBg : THEME.colors.successBg
      : THEME.colors.dangerBg;

  const initials = user.name
    .split(" ")
    .map((word) => word[0])
    .join("")
    .slice(0, 2);

  const avatarBg = isLastAdmin
    ? THEME.colors.primaryLight
    : user.status === "suspended"
      ? "#fee2e2"
      : THEME.colors.successBg;

  const avatarColor = isLastAdmin
    ? THEME.colors.primary
    : user.status === "suspended"
      ? THEME.colors.danger
      : THEME.colors.success;

  return (
    <div
      style={{
        background: THEME.colors.surface,
        border: `1px solid ${THEME.colors.border}`,
        borderRadius: THEME.radii.xl,
        overflow: "hidden",
        opacity: user.status === "suspended" ? 0.7 : 1,
      }}
    >
      {/* Collapsed header */}
      <div
        role="button"
        tabIndex={0}
        aria-expanded={isExpanded}
        aria-label={`${user.name}, ${statusLabel}`}
        onClick={() => setIsExpanded(!isExpanded)}
        onKeyDown={(e) => e.key === "Enter" && setIsExpanded(!isExpanded)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "14px 16px",
          cursor: "pointer",
        }}
      >
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: THEME.radii.lg,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: avatarBg,
            color: avatarColor,
            fontWeight: 800,
            fontSize: 14,
          }}
        >
          {initials}
        </div>

        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontWeight: 700, fontSize: 14, color: THEME.colors.text }}>
              {user.name}
            </span>
            <Badge color={statusColor} bg={statusBg}>
              <StatusDot color={statusColor} /> {statusLabel}
            </Badge>
            {isLastAdmin && (
              <Badge color={THEME.colors.primary} bg={THEME.colors.primaryBg}>
                🔒 SOLE ADMIN
              </Badge>
            )}
          </div>
          <div
            style={{
              fontSize: 12,
              color: THEME.colors.textFaint,
              marginTop: 2,
              fontFamily: THEME.fonts.mono,
            }}
          >
            {user.email}
          </div>
        </div>

        <Badge>{user.role}</Badge>
        <span
          style={{
            color: THEME.colors.textFaint,
            transition: "transform .2s",
            display: "inline-block",
            transform: isExpanded ? "rotate(180deg)" : "none",
          }}
          aria-hidden="true"
        >
          <Icon name="chevronDown" />
        </span>
      </div>

      {/* Expanded details */}
      {isExpanded && (
        <div style={{ borderTop: `1px solid ${THEME.colors.borderLight}`, padding: 16, background: THEME.colors.surfaceAlt }}>
          <div
            style={{
              display: "flex",
              gap: 16,
              marginBottom: 14,
              fontSize: 12,
              color: THEME.colors.textMuted,
              flexWrap: "wrap",
            }}
          >
            <span><Icon name="clock" /> Added {user.created}</span>
            {user.expires && (
              <span style={{ color: isExpired ? THEME.colors.danger : THEME.colors.textMuted }}>
                <Icon name="key" /> {isExpired ? "Expired" : "Expires"} {user.expires}
              </span>
            )}
            <span>
              {user.rules.length} rule{user.rules.length !== 1 ? "s" : ""}
            </span>
          </div>

          {isExpired && user.status === "active" && (
            <WarningBanner severity="error">
              This user's access has expired. Rules are inactive and no new rules can be added. Extend the expiry date or remove the user.
            </WarningBanner>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 14 }}>
            {user.rules.length === 0 && (
              <div style={{ color: THEME.colors.textFaint, fontSize: 13, fontStyle: "italic", padding: "12px 0" }}>
                No access rules — user cannot reach any resources.
              </div>
            )}
            {user.rules.map((rule, index) => (
              <RuleTag
                key={`${rule.target}-${index}`}
                rule={rule}
                nodes={nodes}
                containers={containers}
                onRemove={
                  !isLastAdmin
                    ? () => dispatch({ type: "DELETE_RULE", userId: user.id, ruleIndex: index })
                    : null
                }
              />
            ))}
          </div>

          {!isLastAdmin && (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              <Button
                size="sm"
                disabled={isExpired}
                onClick={() => dispatch({ type: "SET_MODAL", payload: { type: "addRule", userId: user.id } })}
                style={isExpired ? { opacity: 0.4, cursor: "not-allowed" } : {}}
              >
                <Icon name="plus" /> {isExpired ? "Expired — Can't Add" : "Add Rule"}
              </Button>

              <Button
                size="sm"
                variant={user.status === "active" ? "warning" : "success"}
                onClick={() => dispatch({ type: "TOGGLE_STATUS", id: user.id })}
              >
                {user.status === "active" ? (
                  <><Icon name="ban" /> Suspend</>
                ) : (
                  <><Icon name="check" /> Reactivate</>
                )}
              </Button>

              <Button
                size="sm"
                variant="danger"
                onClick={() =>
                  dispatch({
                    type: "SET_MODAL",
                    payload: {
                      type: "dangerConfirm",
                      title: "Remove User?",
                      message: `Permanently remove ${user.name} and all ${user.rules.length} access rule(s). This cannot be undone.`,
                      confirmPhrase: user.email,
                      confirmLabel: "Remove Permanently",
                      onConfirm: () => dispatch({ type: "DELETE_USER", id: user.id }),
                    },
                  })
                }
              >
                <Icon name="trash" /> Remove
              </Button>
            </div>
          )}

          {isLastAdmin && (
            <div
              style={{
                padding: "10px 14px",
                background: THEME.colors.primaryBg,
                border: `1px solid ${THEME.colors.primary}`,
                borderRadius: THEME.radii.lg,
                fontSize: 12,
                color: THEME.colors.primary,
                fontWeight: 600,
              }}
            >
              <Icon name="lock" /> Protected — sole admin account cannot be modified or removed.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Audit Log ───

const SEVERITY_STYLES = {
  info: { color: THEME.colors.primary, bg: THEME.colors.infoBg },
  warn: { color: THEME.colors.warning, bg: THEME.colors.warningBg },
  error: { color: THEME.colors.danger, bg: THEME.colors.dangerBg },
};

function AuditLog({ entries }) {
  return (
    <div role="log" style={{ display: "flex", flexDirection: "column", gap: 1 }}>
      {entries.slice(0, 20).map((entry, index) => {
        const severityStyle = SEVERITY_STYLES[entry.severity] || SEVERITY_STYLES.info;
        return (
          <div
            key={`${entry.timestamp}-${index}`}
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 10,
              padding: "10px 14px",
              background: index % 2 === 0 ? THEME.colors.surface : THEME.colors.surfaceAlt,
              fontSize: 13,
              borderRadius: THEME.radii.sm,
            }}
          >
            <Badge color={severityStyle.color} bg={severityStyle.bg}>
              {entry.severity}
            </Badge>
            <span style={{ flex: 1, color: THEME.colors.textSecondary, lineHeight: 1.5 }}>
              {entry.action}
            </span>
            <time
              dateTime={entry.timestamp}
              style={{
                fontSize: 11,
                color: THEME.colors.textFaint,
                whiteSpace: "nowrap",
                fontFamily: THEME.fonts.mono,
              }}
            >
              {new Date(entry.timestamp).toLocaleString()}
            </time>
          </div>
        );
      })}
    </div>
  );
}

// ─── Infrastructure View ───

function InfrastructureView({ nodes, containers, dispatch }) {
  const [editing, setEditing] = useState(null);
  const [ipError, setIpError] = useState(null);

  const statusColor = (status) =>
    status === "online"
      ? THEME.colors.success
      : status === "planned"
        ? "#6366f1"
        : THEME.colors.danger;

  const commitIP = () => {
    if (!editing) return;
    const { value } = editing;

    if (value === "—" || value === "") {
      setEditing(null);
      setIpError(null);
      return;
    }

    if (!isValidIPv4(value)) {
      setIpError("Invalid IPv4 address");
      return;
    }
    if (isReservedIP(value)) {
      setIpError("Reserved IP — cannot use");
      return;
    }
    if (!isInExpectedSubnet(value)) {
      setIpError(`Outside expected subnet (${EXPECTED_SUBNET}.x)`);
      return;
    }

    dispatch({ type: "SET_IP", kind: editing.kind, id: editing.id, ip: value });
    setEditing(null);
    setIpError(null);
  };

  const renderIPCell = (kind, id, ip) => {
    if (editing?.kind === kind && editing?.id === id) {
      return (
        <div>
          <input
            autoFocus
            value={editing.value}
            onChange={(e) => { setEditing({ ...editing, value: e.target.value }); setIpError(null); }}
            onBlur={commitIP}
            onKeyDown={(e) => {
              if (e.key === "Enter") e.target.blur();
              if (e.key === "Escape") { setEditing(null); setIpError(null); }
            }}
            aria-label={`IP address for ${id}`}
            style={{
              fontSize: 11,
              fontFamily: THEME.fonts.mono,
              border: `1px solid ${ipError ? THEME.colors.danger : THEME.colors.primary}`,
              borderRadius: 3,
              padding: "1px 4px",
              width: 120,
              outline: "none",
            }}
          />
          {ipError && <div style={{ ...styles.errorText, fontSize: 10 }}>{ipError}</div>}
        </div>
      );
    }

    const isPlaceholder = ip === "—";
    return (
      <span
        role="button"
        tabIndex={0}
        onClick={() => { setEditing({ kind, id, value: ip }); setIpError(null); }}
        onKeyDown={(e) => e.key === "Enter" && setEditing({ kind, id, value: ip })}
        title="Click to set IP"
        style={{
          fontSize: 11,
          color: isPlaceholder ? THEME.colors.warning : THEME.colors.textFaint,
          fontFamily: THEME.fonts.mono,
          cursor: "pointer",
          borderBottom: `1px dashed ${THEME.colors.borderInput}`,
        }}
      >
        {isPlaceholder ? "click to set IP" : ip}
      </span>
    );
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 12 }}>
      {nodes.map((node) => {
        const nodeContainers = containers.filter((c) => c.node === node.id);
        const isPlanned = node.status === "planned";

        return (
          <div
            key={node.id}
            style={{
              background: isPlanned ? THEME.colors.purpleBg : THEME.colors.surface,
              border: `1px ${isPlanned ? "dashed" : "solid"} ${isPlanned ? THEME.colors.purpleBorder : THEME.colors.border}`,
              borderRadius: THEME.radii.xl,
              padding: 14,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <span style={{ color: statusColor(node.status) }}><Icon name="server" /></span>
              <span style={{ fontWeight: 700, fontSize: 14, color: THEME.colors.text }}>{node.name}</span>
              <span style={{ marginLeft: "auto" }}><StatusDot color={statusColor(node.status)} /></span>
            </div>

            <div style={{ marginBottom: 8 }}>{renderIPCell("node", node.id, node.ip)}</div>

            <div
              style={{
                fontSize: 11,
                color: THEME.colors.textFaint,
                marginBottom: 6,
                fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: ".04em",
              }}
            >
              {isPlanned ? "Coming soon" : `${nodeContainers.length} containers`}
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {nodeContainers.map((ct) => (
                <div
                  key={ct.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "5px 8px",
                    background: ct.critical ? THEME.colors.warningBg : "#f9fafb",
                    borderRadius: 5,
                    fontSize: 12,
                    border: `1px solid ${ct.critical ? THEME.colors.warningBorder : "#f3f0eb"}`,
                  }}
                >
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      color: ct.kind === "vm" ? THEME.colors.purple : THEME.colors.textFaint,
                      textTransform: "uppercase",
                      minWidth: 20,
                    }}
                  >
                    {ct.kind === "vm" ? "VM" : "CT"}
                  </span>
                  <span style={{ fontWeight: 600, color: THEME.colors.textSecondary, minWidth: 32 }}>{ct.vmid}</span>
                  <span style={{ color: ct.critical ? THEME.colors.warning : THEME.colors.textMuted, flex: 1 }}>
                    {ct.name}
                    {PROTECTED_CONTAINERS.includes(ct.id) && (
                      <span style={{ fontSize: 9, color: THEME.colors.danger, marginLeft: 4, fontWeight: 700 }}>🔒</span>
                    )}
                  </span>
                  {renderIPCell("ct", ct.id, ct.ip)}
                  {ct.critical && <span style={{ fontSize: 9, color: THEME.colors.warning, fontWeight: 700 }}>CRIT</span>}
                </div>
              ))}
              {nodeContainers.length === 0 && (
                <div style={{ fontSize: 12, color: THEME.colors.purpleText, fontStyle: "italic", padding: "8px 0" }}>
                  No containers yet
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Toast ───

function Toast({ toast, onClear }) {
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(onClear, 3000);
    return () => clearTimeout(timer);
  }, [toast, onClear]);

  if (!toast) return null;

  const bgColors = {
    ok: THEME.colors.toastOk,
    warn: THEME.colors.toastWarn,
    error: THEME.colors.toastError,
  };

  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        position: "fixed",
        bottom: 24,
        right: 24,
        background: bgColors[toast.kind] || bgColors.ok,
        color: THEME.colors.surface,
        padding: "12px 20px",
        borderRadius: THEME.radii.lg,
        fontSize: 13,
        fontWeight: 600,
        zIndex: 9999,
        boxShadow: THEME.shadows.toast,
      }}
    >
      {toast.message}
    </div>
  );
}

// ─── Tabs ───

function Tabs({ active, onChange, items }) {
  return (
    <div
      role="tablist"
      style={{
        display: "flex",
        gap: 2,
        background: THEME.colors.muted,
        padding: 3,
        borderRadius: THEME.radii.lg,
        marginBottom: 20,
      }}
    >
      {items.map((item) => (
        <button
          key={item.id}
          role="tab"
          aria-selected={active === item.id}
          onClick={() => onChange(item.id)}
          style={{
            flex: 1,
            padding: "9px 16px",
            border: "none",
            borderRadius: THEME.radii.md,
            background: active === item.id ? THEME.colors.surface : "transparent",
            color: active === item.id ? THEME.colors.text : THEME.colors.textMuted,
            fontWeight: active === item.id ? 700 : 500,
            fontSize: 13,
            cursor: "pointer",
            fontFamily: "inherit",
            transition: "all .15s",
            boxShadow: active === item.id ? THEME.shadows.tab : "none",
          }}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

// ─── Stats Bar ───

function StatsBar({ users }) {
  const expired = users.filter((u) => u.status === "active" && isUserExpired(u)).length;

  const stats = [
    { label: "Users", value: users.length, icon: "user", color: THEME.colors.primary },
    { label: "Active", value: users.filter((u) => u.status === "active").length, icon: "check", color: THEME.colors.success },
    { label: "Suspended", value: users.filter((u) => u.status === "suspended").length, icon: "ban", color: THEME.colors.danger },
    { label: "ACL Rules", value: users.reduce((sum, u) => sum + u.rules.length, 0), icon: "key", color: THEME.colors.purple },
  ];

  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
        {stats.map((stat) => (
          <div
            key={stat.label}
            style={{
              background: THEME.colors.surface,
              border: `1px solid ${THEME.colors.border}`,
              borderRadius: THEME.radii.xl,
              padding: "14px 16px",
              display: "flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <span style={{ color: stat.color }}><Icon name={stat.icon} /></span>
            <div>
              <div style={{ fontSize: 22, fontWeight: 800, color: THEME.colors.text, lineHeight: 1 }}>{stat.value}</div>
              <div
                style={{
                  fontSize: 11,
                  color: THEME.colors.textFaint,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: ".04em",
                }}
              >
                {stat.label}
              </div>
            </div>
          </div>
        ))}
      </div>
      {expired > 0 && (
        <div
          style={{
            marginTop: 8,
            padding: "8px 14px",
            background: THEME.colors.warningBg,
            border: `1px solid ${THEME.colors.warningBorder}`,
            borderRadius: THEME.radii.lg,
            fontSize: 12,
            color: THEME.colors.warningDeep,
            fontWeight: 600,
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          <Icon name="alert" /> {expired} user{expired !== 1 ? "s have" : " has"} expired access — rules inactive but not removed
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════
//  MAIN APP
// ═══════════════════════════════════

const TAB_ITEMS = [
  { id: "users", label: "Users & Access" },
  { id: "infra", label: "Infrastructure" },
  { id: "audit", label: "Audit Log" },
];

// ─── Data Normalizers (API → Component format) ───

function normalizeUsers(apiUsers) {
  return apiUsers.map((u) => ({
    id: u.id,
    name: u.name,
    email: u.email,
    role: (u.role || "developer").toLowerCase(),
    status: (u.status || "active").toLowerCase(),
    created: u.createdAt ? u.createdAt.slice(0, 10) : u.created,
    expires: u.expiresAt ? u.expiresAt.slice(0, 10) : u.expires || null,
    rules: (u.rules || []).map((r) => ({
      id: r.id,
      target: r.targetId || r.target,
      ports: typeof r.ports === "string" ? JSON.parse(r.ports) : r.ports,
      type: (r.targetType || r.type || "lxc").toLowerCase(),
    })),
  }));
}

function normalizeContainers(apiContainers) {
  return apiContainers.map((c) => ({
    id: c.id,
    name: c.name,
    ip: c.ip || "—",
    node: c.nodeId || c.node,
    vmid: c.vmid,
    critical: c.critical || false,
    kind: c.kind || "ct",
  }));
}

function normalizeAudit(apiAudit) {
  return apiAudit.map((e) => ({
    timestamp: e.createdAt || e.timestamp,
    action: e.action,
    severity: (e.severity || "info").toLowerCase(),
  }));
}

/**
 * AccessManager can run in two modes:
 * 1. Standalone (no props) — uses local useReducer with INITIAL_STATE (prototype/demo)
 * 2. API-backed (with initialState + actions props) — optimistic local state + API sync
 */
export default function AccessManager({ initialState: externalState, actions: apiActions } = {}) {
  const initState = externalState
    ? {
        ...INITIAL_STATE,
        users: normalizeUsers(externalState.users || []),
        nodes: externalState.nodes || INITIAL_STATE.nodes,
        containers: normalizeContainers(externalState.containers || []),
        auditLog: normalizeAudit(externalState.auditLog || []),
        lockdownActive: externalState.lockdownActive || false,
      }
    : INITIAL_STATE;

  const [state, dispatch] = useReducer(reducer, initState);
  const [activeTab, setActiveTab] = useState("users");
  const activityRef = useRef(Date.now());

  // Wrap dispatch to also call API actions when available
  const secureDispatch = useCallback(
    (action) => {
      dispatch(action);

      // Fire-and-forget API sync (state already updated optimistically)
      if (!apiActions) return;

      try {
        switch (action.type) {
          case "ADD_USER":
            apiActions.addUser?.({
              name: action.payload.name,
              email: action.payload.email,
              role: action.payload.role.toUpperCase(),
              expiresAt: action.payload.expires,
            });
            break;
          case "DELETE_USER":
            apiActions.deleteUser?.(action.id);
            break;
          case "TOGGLE_STATUS": {
            const user = state.users.find((u) => u.id === action.id);
            if (user) {
              const next = user.status === "active" ? "SUSPENDED" : "ACTIVE";
              apiActions.toggleStatus?.(action.id, next);
            }
            break;
          }
          case "ADD_RULE":
            apiActions.addRule?.({
              userId: action.payload.userId,
              targetType: action.payload.rule.type.toUpperCase(),
              targetId: action.payload.rule.target,
              ports: action.payload.rule.ports,
            });
            break;
          case "DELETE_RULE":
            // For API mode, rules have real IDs; for prototype they use index
            apiActions.deleteRule?.(action.ruleId || action.ruleIndex);
            break;
          case "SET_IP":
            apiActions.setIP?.(action.kind, action.id, action.ip);
            break;
          case "EMERGENCY_LOCKDOWN":
            apiActions.emergencyLockdown?.();
            break;
          case "EMERGENCY_LIFT":
            apiActions.emergencyLift?.();
            break;
          case "MARK_ACL_PUSHED":
            apiActions.pushACL?.();
            break;
        }
      } catch (err) {
        console.error("API sync failed:", err);
      }
    },
    [apiActions, state.users]
  );

  const clearToast = useCallback(() => dispatch({ type: "CLEAR_TOAST" }), []);

  // Session inactivity timeout
  useEffect(() => {
    const resetActivity = () => {
      activityRef.current = Date.now();
      if (state.sessionActive) {
        dispatch({ type: "ACTIVITY_PING" });
      }
    };

    const events = ["mousemove", "keydown", "click", "touchstart"];
    events.forEach((e) => window.addEventListener(e, resetActivity, { passive: true }));

    const interval = setInterval(() => {
      if (state.sessionActive && Date.now() - activityRef.current > SESSION_TIMEOUT_MS) {
        dispatch({ type: "SESSION_TIMEOUT" });
      }
    }, SESSION_CHECK_INTERVAL_MS);

    return () => {
      events.forEach((e) => window.removeEventListener(e, resetActivity));
      clearInterval(interval);
    };
  }, [state.sessionActive]);

  // Periodic expiry check
  useEffect(() => {
    const interval = setInterval(() => {
      dispatch({ type: "CHECK_EXPIRY" });
    }, EXPIRY_CHECK_INTERVAL_MS);

    dispatch({ type: "CHECK_EXPIRY" });

    return () => clearInterval(interval);
  }, []);

  // Compute unpushed changes indicator
  const { json: currentACL } = generateACL(state.users, state.nodes, state.containers);
  const hasUnpushedChanges = state.lastPushedACL !== null && state.lastPushedACL !== currentACL;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700;9..40,800&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-thumb { background: ${THEME.colors.borderInput}; border-radius: 3px; }
      `}</style>

      <div style={{ fontFamily: THEME.fonts.body, background: THEME.colors.bg, minHeight: "100vh", color: THEME.colors.text }}>
        {/* Lockdown Banner */}
        {state.lockdownActive && <LockdownBanner dispatch={secureDispatch} />}

        {/* Header */}
        <header
          style={{
            background: THEME.colors.surface,
            borderBottom: `1px solid ${THEME.colors.border}`,
            padding: "16px 28px",
            display: "flex",
            alignItems: "center",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: THEME.radii.lg,
              background: state.lockdownActive ? THEME.colors.danger : THEME.colors.primary,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: THEME.colors.surface,
            }}
          >
            <Icon name="shield" size={20} />
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: 18, fontWeight: 800, letterSpacing: "-.02em" }}>
              Access Manager
            </h1>
            <span style={{ fontSize: 12, color: THEME.colors.textFaint }}>
              Tailscale ACL control · Proxmox 8.4.16
              {state.lockdownActive && <span style={{ color: THEME.colors.danger, fontWeight: 700, marginLeft: 8 }}>LOCKDOWN</span>}
            </span>
          </div>

          {hasUnpushedChanges && (
            <Badge color={THEME.colors.warning} bg={THEME.colors.warningBg}>
              Unpushed changes
            </Badge>
          )}

          <nav style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            {!state.lockdownActive && (
              <Button
                size="sm"
                variant="dangerSolid"
                onClick={() =>
                  secureDispatch({
                    type: "SET_MODAL",
                    payload: {
                      type: "dangerConfirm",
                      title: "Emergency Lockdown",
                      message:
                        "This will immediately suspend ALL non-admin users and revoke their access to every resource on the network. Only admin accounts will retain access.",
                      confirmPhrase: "LOCKDOWN",
                      confirmLabel: "Activate Lockdown",
                      onConfirm: () => secureDispatch({ type: "EMERGENCY_LOCKDOWN" }),
                    },
                  })
                }
              >
                <Icon name="zap" /> Emergency
              </Button>
            )}
            <Button
              size="sm"
              variant="success"
              onClick={() => secureDispatch({ type: "SET_MODAL", payload: { type: "acl" } })}
            >
              <Icon name="download" /> Export ACL
            </Button>
            <Button
              size="sm"
              variant="primary"
              disabled={state.lockdownActive}
              onClick={() => secureDispatch({ type: "SET_MODAL", payload: { type: "addUser" } })}
            >
              <Icon name="plus" /> Add User
            </Button>
          </nav>
        </header>

        {/* Content */}
        <main style={{ maxWidth: 980, margin: "0 auto", padding: "24px 20px" }}>
          <StatsBar users={state.users} />

          <Tabs active={activeTab} onChange={setActiveTab} items={TAB_ITEMS} />

          {activeTab === "users" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {state.users.map((user) => (
                <UserCard
                  key={user.id}
                  user={user}
                  dispatch={secureDispatch}
                  nodes={state.nodes}
                  containers={state.containers}
                  users={state.users}
                />
              ))}
            </div>
          )}

          {activeTab === "infra" && (
            <>
              <p style={{ marginBottom: 14, fontSize: 13, color: THEME.colors.textMuted }}>
                Proxmox 8.4.16 cluster — 2 active nodes + 1 planned. Click any IP placeholder to set
                the real LAN address. Amber = critical infrastructure. 🔒 = protected (subnet router).
              </p>
              <InfrastructureView
                nodes={state.nodes}
                containers={state.containers}
                dispatch={secureDispatch}
              />
            </>
          )}

          {activeTab === "audit" && (
            <>
              <p style={{ marginBottom: 14, fontSize: 13, color: THEME.colors.textMuted }}>
                All access changes are logged with timestamps and severity. Security events are highlighted.
              </p>
              <div
                style={{
                  background: THEME.colors.surface,
                  border: `1px solid ${THEME.colors.border}`,
                  borderRadius: THEME.radii.xl,
                  overflow: "hidden",
                }}
              >
                <AuditLog entries={state.auditLog} />
              </div>
            </>
          )}
        </main>

        {/* Modals */}
        {state.modal?.type === "addUser" && <AddUserModal dispatch={secureDispatch} />}

        {state.modal?.type === "addRule" && (
          <AddRuleModal
            userId={state.modal.userId}
            dispatch={secureDispatch}
            nodes={state.nodes}
            containers={state.containers}
            users={state.users}
          />
        )}

        {state.modal?.type === "acl" && (
          <ACLPreviewModal
            users={state.users}
            nodes={state.nodes}
            containers={state.containers}
            lastPushedACL={state.lastPushedACL}
            pushHistory={state.pushHistory}
            dispatch={secureDispatch}
          />
        )}

        {state.modal?.type === "confirm" && (
          <ConfirmModal
            title={state.modal.title}
            message={state.modal.message}
            confirmLabel={state.modal.confirmLabel}
            onConfirm={state.modal.onConfirm}
            dispatch={secureDispatch}
          />
        )}

        {state.modal?.type === "dangerConfirm" && (
          <DangerConfirmModal
            title={state.modal.title}
            message={state.modal.message}
            confirmPhrase={state.modal.confirmPhrase}
            confirmLabel={state.modal.confirmLabel}
            onConfirm={state.modal.onConfirm}
            dispatch={secureDispatch}
          />
        )}

        <Toast toast={state.toast} onClear={clearToast} />

        {!state.sessionActive && <SessionTimeoutOverlay dispatch={dispatch} />}
      </div>
    </>
  );
}
