import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";

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
