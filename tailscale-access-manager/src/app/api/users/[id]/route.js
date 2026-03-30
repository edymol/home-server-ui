import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";

// PATCH /api/users/:id — Update user (suspend/reactivate/change role)
export async function PATCH(request, { params }) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = params;
  const body = await request.json();
  const { status, role, expiresAt } = body;

  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  // Lockdown check: block reactivation during lockdown
  if (status === "ACTIVE") {
    const lockdown = await prisma.appState.findUnique({
      where: { key: "lockdownActive" },
    });
    if (lockdown?.value === "true") {
      return NextResponse.json(
        { error: "Cannot reactivate users during lockdown" },
        { status: 403 }
      );
    }
  }

  // Last admin protection
  if (status === "SUSPENDED" && user.role === "ADMIN") {
    const activeAdmins = await prisma.user.count({
      where: { role: "ADMIN", status: "ACTIVE" },
    });
    if (activeAdmins <= 1) {
      return NextResponse.json(
        { error: "Cannot suspend the last admin" },
        { status: 403 }
      );
    }
  }

  const data = {};
  if (status && ["ACTIVE", "SUSPENDED"].includes(status)) data.status = status;
  if (role && ["VIEWER", "DEVELOPER", "MAINTAINER", "ADMIN"].includes(role)) data.role = role;
  if (expiresAt !== undefined) data.expiresAt = expiresAt ? new Date(expiresAt) : null;

  const updated = await prisma.user.update({ where: { id }, data });

  const severity = status === "SUSPENDED" ? "WARN" : "WARN"; // reactivation also warn
  await prisma.auditLog.create({
    data: {
      userId: id,
      action: `User ${user.email} updated: ${JSON.stringify(data)}`,
      severity,
    },
  });

  return NextResponse.json(updated);
}

// DELETE /api/users/:id — Remove user + cascade rules
export async function DELETE(request, { params }) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = params;

  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  // Last admin protection
  if (user.role === "ADMIN") {
    const activeAdmins = await prisma.user.count({
      where: { role: "ADMIN", status: "ACTIVE" },
    });
    if (activeAdmins <= 1) {
      return NextResponse.json(
        { error: "Cannot remove the last admin" },
        { status: 403 }
      );
    }
  }

  await prisma.user.delete({ where: { id } });

  await prisma.auditLog.create({
    data: {
      action: `User ${user.email} removed permanently`,
      severity: "ERROR",
    },
  });

  return NextResponse.json({ success: true });
}
