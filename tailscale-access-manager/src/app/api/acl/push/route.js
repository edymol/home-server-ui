import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth";
import { generateACL } from "@/lib/acl-generator";
import { getACL, pushACL } from "@/lib/tailscale";
import { canPush, recordPush, getPushInfo } from "@/lib/rate-limit";

// POST /api/acl/push — Push ACL to Tailscale API
export async function POST() {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Rate limit check
  if (!canPush()) {
    const info = getPushInfo();
    return NextResponse.json(
      {
        error: `Rate limited — wait ${info.cooldownSeconds}s before next push`,
        cooldownSeconds: info.cooldownSeconds,
      },
      { status: 429 }
    );
  }

  const [users, nodes, containers] = await Promise.all([
    prisma.user.findMany({ include: { rules: true } }),
    prisma.node.findMany(),
    prisma.container.findMany(),
  ]);

  const { policy, json, skipped } = generateACL(users, nodes, containers);

  if (skipped.length > 0) {
    return NextResponse.json(
      {
        error: `Cannot push — ${skipped.length} rules have missing IPs`,
        skipped,
      },
      { status: 400 }
    );
  }

  try {
    // Get current etag to prevent race conditions
    const { etag } = await getACL();

    // Push new policy
    const result = await pushACL(policy, etag);

    // Record push for rate limiting
    recordPush();

    // Store snapshot
    await prisma.aCLSnapshot.create({
      data: {
        aclJson: json,
        etag: result.etag,
        pushedBy: session.user.email,
      },
    });

    await prisma.auditLog.create({
      data: {
        action: `ACL policy pushed to Tailscale by ${session.user.email}`,
        severity: "WARN",
      },
    });

    return NextResponse.json({
      success: true,
      etag: result.etag,
      pushedAt: new Date().toISOString(),
      rateLimit: getPushInfo(),
    });
  } catch (error) {
    await prisma.auditLog.create({
      data: {
        action: `ACL push FAILED: ${error.message}`,
        severity: "ERROR",
      },
    });

    return NextResponse.json(
      { error: error.message },
      { status: error.message.includes("conflict") ? 409 : 500 }
    );
  }
}
