/**
 * Generate Tailscale ACL JSON from database state.
 * Security-hardened: skips expired users, placeholder IPs, forbidden ports.
 */

const FORBIDDEN_PORTS = [3100]; // Access Manager itself

export function generateACL(users, nodes, containers) {
  const acls = [];
  const skipped = [];
  const tagOwners = {
    "tag:admin": [],
    "tag:maintainer": [],
    "tag:developer": [],
    "tag:viewer": [],
  };

  const now = new Date();

  // Only active, non-expired users
  const activeUsers = users.filter((user) => {
    if (user.status !== "ACTIVE") return false;
    if (user.expiresAt && new Date(user.expiresAt) < now) return false;
    return true;
  });

  activeUsers.forEach((user) => {
    const tagKey = `tag:${user.role.toLowerCase()}`;
    if (tagOwners[tagKey] && !tagOwners[tagKey].includes(user.email)) {
      tagOwners[tagKey].push(user.email);
    }

    user.rules.forEach((rule) => {
      // Filter out forbidden ports
      const ports = JSON.parse(rule.ports).filter(
        (p) => !FORBIDDEN_PORTS.includes(p)
      );
      if (ports.length === 0) return;

      if (rule.targetType === "ALL") {
        acls.push({
          action: "accept",
          src: [user.email],
          dst: ["10.0.0.0/24:*"],
          comment: `${user.name} — full access`,
        });
        return;
      }

      if (rule.targetType === "NODE") {
        const node = nodes.find((n) => n.id === rule.targetId);
        if (!node) return;

        if (!node.ip || node.ip === "—") {
          skipped.push({ name: node.name, reason: "no IP" });
          return;
        }

        const nodeContainers = containers.filter((c) => c.nodeId === rule.targetId);
        const validContainers = nodeContainers.filter((c) => c.ip && c.ip !== "—");
        const skippedContainers = nodeContainers.filter((c) => !c.ip || c.ip === "—");

        skippedContainers.forEach((c) =>
          skipped.push({ name: c.name, reason: "no IP" })
        );

        const allIPs = [node.ip, ...validContainers.map((c) => c.ip)];
        ports.forEach((port) => {
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

      if (rule.targetType === "LXC") {
        const container = containers.find((c) => c.id === rule.targetId);
        if (!container) return;

        if (!container.ip || container.ip === "—") {
          skipped.push({ name: container.name, reason: "no IP" });
          return;
        }

        ports.forEach((port) => {
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

  return {
    policy: { acls: merged, tagOwners },
    json: JSON.stringify({ acls: merged, tagOwners }, null, 2),
    skipped,
  };
}
