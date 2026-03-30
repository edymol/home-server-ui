import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { validateIP } from "@/lib/validators";

// PATCH /api/infra/nodes/:id — Update node IP
export async function PATCH(request, { params }) {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = params;
  const body = await request.json();
  const { ip } = body;

  if (ip) {
    const ipError = validateIP(ip);
    if (ipError) {
      return NextResponse.json({ error: ipError }, { status: 400 });
    }
  }

  const node = await prisma.node.update({
    where: { id },
    data: { ip: ip || "" },
  });

  return NextResponse.json(node);
}
