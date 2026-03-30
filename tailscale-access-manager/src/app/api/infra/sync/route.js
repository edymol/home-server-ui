import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { execSync } from "child_process";

const PVE_URL = process.env.PROXMOX_API_URL;
const PVE_TOKEN = `${process.env.PROXMOX_TOKEN_ID}=${process.env.PROXMOX_TOKEN_SECRET}`;

function pveFetch(path) {
  const cmd = `curl -sk --connect-timeout 5 -m 10 -H "Authorization: PVEAPIToken=${PVE_TOKEN}" "${PVE_URL}/api2/json${path}"`;
  const result = execSync(cmd, { encoding: "utf-8", timeout: 12000 });
  return JSON.parse(result).data;
}

function getContainerIP(nodeId, kind, vmid) {
  try {
    const path = kind === "vm"
      ? `/nodes/${nodeId}/qemu/${vmid}/config`
      : `/nodes/${nodeId}/lxc/${vmid}/config`;
    const config = pveFetch(path);
    const net = config.net0 || config.ipconfig0 || "";
    const match = net.match(/ip=([0-9.]+)/);
    return match ? match[1] : "";
  } catch {
    return "";
  }
}

// POST /api/infra/sync — Sync nodes and containers from Proxmox
export async function POST() {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!PVE_URL || !process.env.PROXMOX_TOKEN_ID) {
    return NextResponse.json({ error: "Proxmox API not configured" }, { status: 500 });
  }

  const errors = [];

  try {
    const pveNodes = pveFetch("/nodes");
    const syncedNodes = [];
    const syncedContainers = [];

    // Get node IPs from their network config
    function getNodeIP(nodeId) {
      try {
        const net = pveFetch(`/nodes/${nodeId}/network`);
        const iface = net.find((n) => n.iface === "vmbr0" || n.type === "bridge");
        if (iface && iface.address) return iface.address;
      } catch {}
      return "";
    }

    for (const pveNode of pveNodes) {
      const nodeId = pveNode.node;
      const nodeIp = getNodeIP(nodeId);

      await prisma.node.upsert({
        where: { id: nodeId },
        update: { name: nodeId, status: pveNode.status === "online" ? "online" : "offline", ip: nodeIp },
        create: { id: nodeId, name: nodeId, status: pveNode.status === "online" ? "online" : "offline", ip: nodeIp },
      });
      syncedNodes.push(nodeId);

      // Fetch LXC containers — list only, get IPs in batch after
      try {
        const lxcList = pveFetch(`/nodes/${nodeId}/lxc`);
        for (const lxc of lxcList) {
          const ctId = `ct${lxc.vmid}`;
          const ip = getContainerIP(nodeId, "ct", lxc.vmid);

          await prisma.container.upsert({
            where: { id: ctId },
            update: { name: lxc.name || `ct-${lxc.vmid}`, ip, nodeId, vmid: lxc.vmid, kind: "ct" },
            create: { id: ctId, name: lxc.name || `ct-${lxc.vmid}`, ip, nodeId, vmid: lxc.vmid, critical: false, kind: "ct" },
          });
          syncedContainers.push({ id: ctId, name: lxc.name, node: nodeId });
        }
      } catch (e) {
        errors.push(`LXC on ${nodeId}: ${e.message}`);
      }

      // Fetch VMs
      try {
        const vmList = pveFetch(`/nodes/${nodeId}/qemu`);
        for (const vm of vmList) {
          const vmId = `vm${vm.vmid}`;
          const ip = getContainerIP(nodeId, "vm", vm.vmid);

          await prisma.container.upsert({
            where: { id: vmId },
            update: { name: vm.name || `vm-${vm.vmid}`, ip, nodeId, vmid: vm.vmid, kind: "vm" },
            create: { id: vmId, name: vm.name || `vm-${vm.vmid}`, ip, nodeId, vmid: vm.vmid, critical: false, kind: "vm" },
          });
          syncedContainers.push({ id: vmId, name: vm.name, node: nodeId });
        }
      } catch (e) {
        errors.push(`VMs on ${nodeId}: ${e.message}`);
      }
    }

    await prisma.auditLog.create({
      data: {
        action: `Proxmox sync: ${syncedNodes.length} nodes, ${syncedContainers.length} containers/VMs${errors.length ? ` (${errors.length} errors)` : ""}`,
        severity: errors.length ? "WARN" : "INFO",
      },
    });

    return NextResponse.json({
      success: true,
      nodes: syncedNodes.length,
      containers: syncedContainers.length,
      errors: errors.length ? errors : undefined,
    });
  } catch (err) {
    return NextResponse.json({ error: `Proxmox sync failed: ${err.message}` }, { status: 500 });
  }
}
