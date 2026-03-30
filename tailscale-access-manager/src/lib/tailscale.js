const BASE_URL = "https://api.tailscale.com/api/v2";

function getHeaders() {
  const apiKey = process.env.TAILSCALE_API_KEY;
  if (!apiKey) throw new Error("TAILSCALE_API_KEY not configured");

  return {
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  };
}

function getTailnet() {
  const tailnet = process.env.TAILSCALE_TAILNET;
  if (!tailnet) throw new Error("TAILSCALE_TAILNET not configured");
  return tailnet;
}

/**
 * Get current ACL policy from Tailscale
 */
export async function getACL() {
  const res = await fetch(
    `${BASE_URL}/tailnet/${getTailnet()}/acl`,
    {
      headers: getHeaders(),
      cache: "no-store",
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Tailscale API error (${res.status}): ${text}`);
  }

  const etag = res.headers.get("etag");
  const body = await res.json();
  return { acl: body, etag };
}

/**
 * Push ACL policy to Tailscale (with etag for conflict prevention)
 */
export async function pushACL(aclJson, etag) {
  const headers = getHeaders();
  if (etag) {
    headers["If-Match"] = etag;
  }

  const res = await fetch(
    `${BASE_URL}/tailnet/${getTailnet()}/acl`,
    {
      method: "POST",
      headers,
      body: typeof aclJson === "string" ? aclJson : JSON.stringify(aclJson),
    }
  );

  if (!res.ok) {
    const text = await res.text();

    if (res.status === 412) {
      throw new Error(
        "ACL conflict: policy was modified externally. Refresh and try again."
      );
    }

    throw new Error(`Tailscale API error (${res.status}): ${text}`);
  }

  const newEtag = res.headers.get("etag");
  return { success: true, etag: newEtag };
}

/**
 * List devices on tailnet
 */
export async function listDevices() {
  const res = await fetch(
    `${BASE_URL}/tailnet/${getTailnet()}/devices`,
    {
      headers: getHeaders(),
      cache: "no-store",
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Tailscale API error (${res.status}): ${text}`);
  }

  return res.json();
}

/**
 * Remove a device from the tailnet
 */
export async function removeDevice(deviceId) {
  const res = await fetch(
    `${BASE_URL}/device/${deviceId}`,
    {
      method: "DELETE",
      headers: getHeaders(),
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Tailscale API error (${res.status}): ${text}`);
  }

  return { success: true };
}
