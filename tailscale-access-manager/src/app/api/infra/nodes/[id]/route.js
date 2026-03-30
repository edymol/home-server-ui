import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { validateIP } from "@/lib/validators";

// PATCH /api/infra/nodes/:id — Update node
export async function PATCH(request, { params }) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = params;
  const body = await request.json();
  const { ip, name, status } = body;

  if (ip) {
    const ipError = validateIP(ip);
    if (ipError) {
      return NextResponse.json({ error: ipError }, { status: 400 });
    }
  }

  const data = {};
  if (ip !== undefined) data.ip = ip || "";
  if (name !== undefined) data.name = name;
  if (status !== undefined) data.status = status;

  const node = await prisma.node.update({ where: { id }, data });
  return NextResponse.json(node);
}

// DELETE /api/infra/nodes/:id — Delete node and its containers
export async function DELETE(request, { params }) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = params;

  // Delete all containers on this node first
  await prisma.container.deleteMany({ where: { nodeId: id } });
  await prisma.node.delete({ where: { id } });

  await prisma.auditLog.create({
    data: {
      action: `Node '${id}' and all its containers deleted`,
      severity: "WARN",
    },
  });

  return NextResponse.json({ success: true });
}
