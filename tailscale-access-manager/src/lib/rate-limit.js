/**
 * Simple in-memory rate limiter for ACL pushes.
 * Persists across requests within the same server process.
 */

const WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const MAX_PUSHES = 3;

const pushTimestamps = [];

export function canPush() {
  const now = Date.now();
  // Clean old entries
  while (pushTimestamps.length > 0 && now - pushTimestamps[0] > WINDOW_MS) {
    pushTimestamps.shift();
  }
  return pushTimestamps.length < MAX_PUSHES;
}

export function recordPush() {
  pushTimestamps.push(Date.now());
}

export function getPushInfo() {
  const now = Date.now();
  while (pushTimestamps.length > 0 && now - pushTimestamps[0] > WINDOW_MS) {
    pushTimestamps.shift();
  }

  const remaining = MAX_PUSHES - pushTimestamps.length;
  const cooldownMs =
    pushTimestamps.length >= MAX_PUSHES
      ? pushTimestamps[0] + WINDOW_MS - now
      : 0;

  return {
    allowed: remaining > 0,
    remaining,
    cooldownSeconds: Math.max(0, Math.ceil(cooldownMs / 1000)),
    totalPushes: pushTimestamps.length,
  };
}
