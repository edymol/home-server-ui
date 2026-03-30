import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { validateIP } from "@/lib/validators";

// GET /api/infra/nodes — List all nodes
export async function GET() {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const nodes = await prisma.node.findMany({ orderBy: { name: "asc" } });
  return NextResponse.json(nodes);
}

// POST /api/infra/nodes — Create a node
export async function POST(request) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const { name, ip, status } = body;

  if (!name) {
    return NextResponse.json({ error: "Node name is required" }, { status: 400 });
  }

  if (ip) {
    const ipError = validateIP(ip);
    if (ipError) {
      return NextResponse.json({ error: ipError }, { status: 400 });
    }
  }

  const id = name.toLowerCase().replace(/[^a-z0-9-]/g, "-");

  const node = await prisma.node.create({
    data: { id, name, ip: ip || "", status: status || "online" },
  });

  await prisma.auditLog.create({
    data: {
      action: `Node '${name}' created (IP: ${ip || "none"})`,
      severity: "INFO",
    },
  });

  return NextResponse.json(node, { status: 201 });
}
