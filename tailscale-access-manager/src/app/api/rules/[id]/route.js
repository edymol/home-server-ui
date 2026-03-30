import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";

// DELETE /api/rules/:id — Remove access rule
export async function DELETE(request, { params }) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = params;

  const rule = await prisma.rule.findUnique({
    where: { id },
    include: { user: true },
  });
  if (!rule) {
    return NextResponse.json({ error: "Rule not found" }, { status: 404 });
  }

  await prisma.rule.delete({ where: { id } });

  // Resolve target name
  let targetName = rule.targetId;
  if (rule.targetType === "NODE") {
    const node = await prisma.node.findUnique({ where: { id: rule.targetId } });
    targetName = node?.name || rule.targetId;
  } else if (rule.targetType === "LXC") {
    const ct = await prisma.container.findUnique({ where: { id: rule.targetId } });
    targetName = ct?.name || rule.targetId;
  }

  await prisma.auditLog.create({
    data: {
      userId: rule.userId,
      action: `Rule removed for ${rule.user.email}: ${targetName} ports ${rule.ports}`,
      severity: "WARN",
    },
  });

  return NextResponse.json({ success: true });
}
