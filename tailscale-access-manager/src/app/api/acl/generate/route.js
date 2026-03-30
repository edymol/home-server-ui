import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { generateACL } from "@/lib/acl-generator";

// POST /api/acl/generate — Generate ACL JSON preview
export async function POST() {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const [users, nodes, containers, lastSnapshot] = await Promise.all([
    prisma.user.findMany({ include: { rules: true } }),
    prisma.node.findMany(),
    prisma.container.findMany(),
    prisma.aCLSnapshot.findFirst({ orderBy: { createdAt: "desc" } }),
  ]);

  const { policy, json, skipped } = generateACL(users, nodes, containers);

  return NextResponse.json({
    json,
    policy,
    skipped,
    lastPushedAt: lastSnapshot?.createdAt || null,
    hasChanges: lastSnapshot ? lastSnapshot.aclJson !== json : true,
  });
}
