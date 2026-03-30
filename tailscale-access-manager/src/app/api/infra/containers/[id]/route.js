import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { validateIP } from "@/lib/validators";

// PATCH /api/infra/containers/:id — Update container
export async function PATCH(request, { params }) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = params;
  const body = await request.json();
  const { ip, name, critical } = body;

  if (ip) {
    const ipError = validateIP(ip);
    if (ipError) {
      return NextResponse.json({ error: ipError }, { status: 400 });
    }
  }

  const data = {};
  if (ip !== undefined) data.ip = ip || "";
  if (name !== undefined) data.name = name;
  if (critical !== undefined) data.critical = critical;

  const container = await prisma.container.update({ where: { id }, data });
  return NextResponse.json(container);
}

// DELETE /api/infra/containers/:id — Delete container
export async function DELETE(request, { params }) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = params;

  // Remove any access rules referencing this container
  await prisma.rule.deleteMany({ where: { targetId: id } });
  await prisma.container.delete({ where: { id } });

  await prisma.auditLog.create({
    data: {
      action: `Container '${id}' deleted`,
      severity: "WARN",
    },
  });

  return NextResponse.json({ success: true });
}
