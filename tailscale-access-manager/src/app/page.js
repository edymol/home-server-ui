"use client";

import { useEffect, useState, useCallback } from "react";
import AccessManager from "./components/AccessManager";

async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (res.status === 401) {
    window.location.href = "/api/auth/signin?callbackUrl=" + encodeURIComponent(window.location.origin);
    throw new Error("Redirecting to login...");
  }

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export default function Home() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [state, setState] = useState(null);

  const loadData = useCallback(async () => {
    try {
      const [users, nodes, containers, audit, emergency] = await Promise.all([
        apiFetch("/api/users"),
        apiFetch("/api/infra/nodes"),
        apiFetch("/api/infra/containers"),
        apiFetch("/api/audit?limit=20"),
        apiFetch("/api/emergency"),
      ]);

      setState({
        users,
        nodes,
        containers,
        auditLog: audit.entries,
        lockdownActive: emergency.lockdownActive,
      });
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // API action handlers passed to the AccessManager component
  const actions = {
    addUser: async (payload) => {
      await apiFetch("/api/users", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      await loadData();
    },

    deleteUser: async (id) => {
      await apiFetch(`/api/users/${id}`, { method: "DELETE" });
      await loadData();
    },

    toggleStatus: async (id, newStatus) => {
      await apiFetch(`/api/users/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: newStatus }),
      });
      await loadData();
    },

    addRule: async (payload) => {
      await apiFetch("/api/rules", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      await loadData();
    },

    deleteRule: async (ruleId) => {
      await apiFetch(`/api/rules/${ruleId}`, { method: "DELETE" });
      await loadData();
    },

    syncProxmox: async () => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 60000);
        const res = await fetch("/api/infra/sync", {
          method: "POST",
          signal: controller.signal,
        });
        clearTimeout(timeout);
        if (res.ok) {
          const data = await res.json();
          console.log("Proxmox sync:", data);
        }
      } catch (e) {
        console.log("Sync request finished (may have timed out on client, data still saved)");
      }
      await loadData();
    },

    addNode: async (payload) => {
      await apiFetch("/api/infra/nodes", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      await loadData();
    },

    deleteNode: async (id) => {
      await apiFetch(`/api/infra/nodes/${id}`, { method: "DELETE" });
      await loadData();
    },

    addContainer: async (payload) => {
      await apiFetch("/api/infra/containers", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      await loadData();
    },

    deleteContainer: async (id) => {
      await apiFetch(`/api/infra/containers/${id}`, { method: "DELETE" });
      await loadData();
    },

    setIP: async (kind, id, ip) => {
      const endpoint =
        kind === "node"
          ? `/api/infra/nodes/${id}`
          : `/api/infra/containers/${id}`;
      await apiFetch(endpoint, {
        method: "PATCH",
        body: JSON.stringify({ ip }),
      });
      await loadData();
    },

    generateACL: async () => {
      return apiFetch("/api/acl/generate", { method: "POST" });
    },

    pushACL: async () => {
      const result = await apiFetch("/api/acl/push", { method: "POST" });
      await loadData();
      return result;
    },

    emergencyLockdown: async () => {
      await apiFetch("/api/emergency", {
        method: "POST",
        body: JSON.stringify({ action: "lockdown" }),
      });
      await loadData();
    },

    emergencyLift: async () => {
      await apiFetch("/api/emergency", {
        method: "POST",
        body: JSON.stringify({ action: "lift" }),
      });
      await loadData();
    },
  };

  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "100vh",
          fontFamily: "'DM Sans', sans-serif",
          color: "#6b7280",
        }}
      >
        Loading Access Manager...
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "100vh",
          fontFamily: "'DM Sans', sans-serif",
          gap: 12,
        }}
      >
        <div style={{ fontSize: 18, fontWeight: 700, color: "#b91c1c" }}>
          Failed to load
        </div>
        <div style={{ fontSize: 14, color: "#6b7280" }}>{error}</div>
        <button
          onClick={() => {
            setError(null);
            setLoading(true);
            loadData();
          }}
          style={{
            marginTop: 8,
            padding: "8px 16px",
            background: "#2563eb",
            color: "#fff",
            border: "none",
            borderRadius: 6,
            fontWeight: 600,
            cursor: "pointer",
            fontFamily: "inherit",
          }}
        >
          Retry
        </button>
      </div>
    );
  }

  return <AccessManager initialState={state} actions={actions} />;
}
