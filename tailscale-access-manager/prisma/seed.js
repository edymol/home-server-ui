const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
  // ─── Nodes ───
  const nodes = [
    { id: "pve", name: "pve", ip: "10.0.0.27", status: "online" },
    { id: "proxmox2", name: "proxmox2", ip: "10.0.0.72", status: "online" },
    { id: "proxmox", name: "proxmox", ip: "10.0.0.28", status: "online" },
  ];

  for (const node of nodes) {
    await prisma.node.upsert({
      where: { id: node.id },
      update: node,
      create: node,
    });
  }

  // ─── Containers ───
  const containers = [
    { id: "ct1001", name: "app-1",         ip: "10.0.0.96",  nodeId: "pve",      vmid: 1001, critical: false, kind: "ct" },
    { id: "ct1003", name: "app-2",      ip: "",              nodeId: "pve",      vmid: 1003, critical: false, kind: "ct" },
    { id: "ct1005", name: "app-3-dev",        ip: "10.0.0.94",  nodeId: "pve",      vmid: 1005, critical: false, kind: "ct" },
    { id: "ct3001", name: "keycloak",       ip: "10.0.0.30",  nodeId: "pve",      vmid: 3001, critical: true,  kind: "ct" },
    { id: "ct3002", name: "web-app",     ip: "",              nodeId: "pve",      vmid: 3002, critical: false, kind: "ct" },
    { id: "ct3005", name: "nginx",          ip: "",              nodeId: "pve",      vmid: 3005, critical: true,  kind: "ct" },
    { id: "ct4000", name: "portal",      ip: "",              nodeId: "pve",      vmid: 4000, critical: false, kind: "ct" },
    { id: "ct6000", name: "backend-1",       ip: "",              nodeId: "pve",      vmid: 6000, critical: false, kind: "ct" },
    { id: "ct105",  name: "tailscale-exit", ip: "10.0.0.155", nodeId: "proxmox2", vmid: 105,  critical: true,  kind: "ct" },
    { id: "ct2000", name: "property",       ip: "",              nodeId: "proxmox2", vmid: 2000, critical: false, kind: "ct" },
    { id: "ct5000", name: "jenkins",        ip: "10.0.0.97",  nodeId: "proxmox2", vmid: 5000, critical: true,  kind: "ct" },
    { id: "ct5001", name: "jenkins-agent",  ip: "",              nodeId: "proxmox2", vmid: 5001, critical: false, kind: "ct" },
    { id: "vm500",  name: "k3s-1",          ip: "10.0.0.101", nodeId: "proxmox2", vmid: 500,  critical: false, kind: "vm" },
    { id: "ct9000", name: "ubuntu-test",    ip: "",              nodeId: "proxmox2", vmid: 9000, critical: false, kind: "ct" },
    { id: "ct1002", name: "sonarqube",      ip: "10.0.0.98",  nodeId: "proxmox",  vmid: 1002, critical: false, kind: "ct" },
    { id: "ct1004", name: "app-3",            ip: "10.0.0.172", nodeId: "proxmox",  vmid: 1004, critical: false, kind: "ct" },
  ];

  for (const ct of containers) {
    await prisma.container.upsert({
      where: { id: ct.id },
      update: ct,
      create: ct,
    });
  }

  // ─── Admin User ───
  const admin = await prisma.user.upsert({
    where: { email: "admin@example.com" },
    update: {},
    create: {
      name: "Admin",
      email: "admin@example.com",
      role: "ADMIN",
      status: "ACTIVE",
      expiresAt: null,
    },
  });

  // ─── Admin full-access rule ───
  const existingRules = await prisma.rule.findMany({ where: { userId: admin.id } });
  if (existingRules.length === 0) {
    await prisma.rule.create({
      data: {
        userId: admin.id,
        targetType: "ALL",
        targetId: "*",
        ports: JSON.stringify([22, 80, 443, 3000, 5432, 6379, 8006, 8080]),
      },
    });
  }

  // ─── Initial lockdown state ───
  await prisma.appState.upsert({
    where: { key: "lockdownActive" },
    update: {},
    create: { key: "lockdownActive", value: "false" },
  });

  // ─── Seed audit entry ───
  await prisma.auditLog.create({
    data: {
      action: "System initialized — database seeded with infrastructure data",
      severity: "INFO",
    },
  });

  console.log("Database seeded successfully.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
