import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import {
  validatePorts,
  isProtectedContainer,
  hasCriticalPorts,
} from "@/lib/validators";

// POST /api/rules — Add access rule to user
export async function POST(request) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Check lockdown
  const lockdown = await prisma.appState.findUnique({
    where: { key: "lockdownActive" },
  });
  if (lockdown?.value === "true") {
    return NextResponse.json(
      { error: "Action blocked — lockdown is active" },
      { status: 403 }
    );
  }

  const body = await request.json();
  const { userId, targetType, targetId, ports } = body;

  // Validate target type
  if (!["NODE", "LXC", "ALL"].includes(targetType)) {
    return NextResponse.json({ error: "Invalid target type" }, { status: 400 });
  }

  // Validate ports
  const parsedPorts = Array.isArray(ports)
    ? ports.map(Number)
    : JSON.parse(ports).map(Number);
  const portError = validatePorts(parsedPorts);
  if (portError) {
    return NextResponse.json({ error: portError }, { status: 400 });
  }

  // Check user exists and is not expired
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }
  if (user.expiresAt && new Date(user.expiresAt) < new Date()) {
    return NextResponse.json(
      { error: "Cannot add rules to expired user — extend expiry first" },
      { status: 403 }
    );
  }

  const rule = await prisma.rule.create({
    data: {
      userId,
      targetType,
      targetId,
      ports: JSON.stringify(parsedPorts),
    },
  });

  // Determine audit severity
  const isProtected = isProtectedContainer(targetId);
  const isCritical = hasCriticalPorts(parsedPorts);
  const isAll = targetType === "ALL";
  let severity = "INFO";
  if (isCritical) severity = "WARN";
  if (isAll || isProtected) severity = "ERROR";

  // Resolve target name for audit
  let targetName = targetId;
  if (targetType === "NODE") {
    const node = await prisma.node.findUnique({ where: { id: targetId } });
    targetName = node?.name || targetId;
  } else if (targetType === "LXC") {
    const ct = await prisma.container.findUnique({ where: { id: targetId } });
    targetName = ct?.name || targetId;
  }

  await prisma.auditLog.create({
    data: {
      userId,
      action: `Rule added for ${user.email}: ${targetName} ports [${parsedPorts}]${isProtected ? " ⚠ PROTECTED CONTAINER" : ""}`,
      severity,
    },
  });

  return NextResponse.json(rule, { status: 201 });
}
