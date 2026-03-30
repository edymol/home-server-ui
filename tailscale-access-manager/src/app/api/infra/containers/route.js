import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { validateIP } from "@/lib/validators";

// GET /api/infra/containers — List all containers
export async function GET() {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const containers = await prisma.container.findMany({
    orderBy: [{ nodeId: "asc" }, { vmid: "asc" }],
  });
  return NextResponse.json(containers);
}

// POST /api/infra/containers — Create a container
export async function POST(request) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const { name, ip, nodeId, vmid, critical, kind } = body;

  if (!name || !nodeId || vmid === undefined) {
    return NextResponse.json(
      { error: "name, nodeId, and vmid are required" },
      { status: 400 }
    );
  }

  // Verify node exists
  const node = await prisma.node.findUnique({ where: { id: nodeId } });
  if (!node) {
    return NextResponse.json({ error: `Node '${nodeId}' not found` }, { status: 400 });
  }

  if (ip) {
    const ipError = validateIP(ip);
    if (ipError) {
      return NextResponse.json({ error: ipError }, { status: 400 });
    }
  }

  const id = `${kind || "ct"}${vmid}`;

  const container = await prisma.container.create({
    data: {
      id,
      name,
      ip: ip || "",
      nodeId,
      vmid: parseInt(vmid),
      critical: critical || false,
      kind: kind || "ct",
    },
  });

  await prisma.auditLog.create({
    data: {
      action: `Container '${name}' (${kind || "ct"}${vmid}) created on node '${nodeId}'`,
      severity: "INFO",
    },
  });

  return NextResponse.json(container, { status: 201 });
}
