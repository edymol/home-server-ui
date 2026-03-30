import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";

// POST /api/emergency — Activate or lift emergency lockdown
export async function POST(request) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const { action } = body; // "lockdown" or "lift"

  if (action === "lockdown") {
    // Suspend all non-admin users
    const affected = await prisma.user.findMany({
      where: { role: { not: "ADMIN" }, status: "ACTIVE" },
    });

    await prisma.user.updateMany({
      where: { role: { not: "ADMIN" } },
      data: { status: "SUSPENDED" },
    });

    await prisma.appState.upsert({
      where: { key: "lockdownActive" },
      update: { value: "true" },
      create: { key: "lockdownActive", value: "true" },
    });

    const emails = affected.map((u) => u.email);
    await prisma.auditLog.create({
      data: {
        action: `EMERGENCY LOCKDOWN activated by ${session.user.email}. Affected: [${emails.join(", ")}]`,
        severity: "ERROR",
      },
    });

    return NextResponse.json({
      success: true,
      action: "lockdown",
      affected: emails.length,
    });
  }

  if (action === "lift") {
    await prisma.appState.upsert({
      where: { key: "lockdownActive" },
      update: { value: "false" },
      create: { key: "lockdownActive", value: "false" },
    });

    await prisma.auditLog.create({
      data: {
        action: `LOCKDOWN LIFTED by ${session.user.email}. Users remain suspended until manually reactivated.`,
        severity: "WARN",
      },
    });

    return NextResponse.json({ success: true, action: "lift" });
  }

  return NextResponse.json(
    { error: 'Invalid action — use "lockdown" or "lift"' },
    { status: 400 }
  );
}

// GET /api/emergency — Check lockdown status
export async function GET() {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const state = await prisma.appState.findUnique({
    where: { key: "lockdownActive" },
  });

  return NextResponse.json({
    lockdownActive: state?.value === "true",
  });
}
