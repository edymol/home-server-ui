import { NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth";
import { listDevices } from "@/lib/tailscale";

// GET /api/tailscale/devices — Proxy to Tailscale device list
export async function GET() {
  const session = await requireAuth();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const data = await listDevices();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json(
      { error: error.message },
      { status: 502 }
    );
  }
}
