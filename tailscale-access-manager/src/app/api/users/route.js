import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { isValidEmail, isValidName, sanitizeName } from "@/lib/validators";

// GET /api/users — List all users with rules
export async function GET() {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const users = await prisma.user.findMany({
    include: { rules: true },
    orderBy: { createdAt: "asc" },
  });

  return NextResponse.json(users);
}

// POST /api/users — Add user
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
  const { name, email, role, expiresAt } = body;

  // Validate
  if (!isValidName(name)) {
    return NextResponse.json(
      { error: "Invalid name (2-64 chars, no special characters)" },
      { status: 400 }
    );
  }

  if (!isValidEmail(email)) {
    return NextResponse.json(
      { error: "Invalid email address" },
      { status: 400 }
    );
  }

  if (!["VIEWER", "DEVELOPER", "MAINTAINER", "ADMIN"].includes(role)) {
    return NextResponse.json({ error: "Invalid role" }, { status: 400 });
  }

  if (expiresAt && new Date(expiresAt) <= new Date()) {
    return NextResponse.json(
      { error: "Expiry date must be in the future" },
      { status: 400 }
    );
  }

  // Duplicate check
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return NextResponse.json(
      { error: "User with this email already exists" },
      { status: 409 }
    );
  }

  const user = await prisma.user.create({
    data: {
      name: sanitizeName(name),
      email: email.trim().toLowerCase(),
      role,
      expiresAt: expiresAt ? new Date(expiresAt) : null,
    },
  });

  await prisma.auditLog.create({
    data: {
      userId: user.id,
      action: `User ${email} added as ${role}`,
      severity: "INFO",
    },
  });

  return NextResponse.json(user, { status: 201 });
}
