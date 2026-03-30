const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const NAME_FORBIDDEN = /[<>{}"'`\\]/;
const EXPECTED_SUBNET = "10.0.0";

const RESERVED_IPS = [
  "0.0.0.0",
  "127.0.0.1",
  "255.255.255.255",
  "10.0.0.255",
  "10.0.0.0",
];

const CRITICAL_PORTS = [5432, 6379, 8006];
const FORBIDDEN_PORTS = [3100];
const PROTECTED_CONTAINERS = ["ct105"]; // Tailscale exit node

export function isValidEmail(email) {
  return EMAIL_RE.test((email || "").trim());
}

export function isValidIPv4(ip) {
  if (!IPV4_RE.test(ip)) return false;
  return ip.split(".").every((octet) => {
    const n = parseInt(octet, 10);
    return n >= 0 && n <= 255;
  });
}

export function isReservedIP(ip) {
  return RESERVED_IPS.includes(ip);
}

export function isInExpectedSubnet(ip) {
  return ip.startsWith(EXPECTED_SUBNET + ".");
}

export function isValidName(name) {
  const trimmed = (name || "").trim();
  return trimmed.length >= 2 && trimmed.length <= 64 && !NAME_FORBIDDEN.test(trimmed);
}

export function sanitizeName(name) {
  return (name || "").trim().replace(/[\x00-\x1f]/g, "");
}

export function validateIP(ip) {
  if (!isValidIPv4(ip)) return "Invalid IPv4 address format";
  if (isReservedIP(ip)) return "Reserved IP address cannot be used";
  if (!isInExpectedSubnet(ip))
    return `IP outside expected subnet (${EXPECTED_SUBNET}.x)`;
  return null;
}

export function validatePorts(ports) {
  if (!Array.isArray(ports) || ports.length === 0) {
    return "At least one port is required";
  }
  const forbidden = ports.filter((p) => FORBIDDEN_PORTS.includes(p));
  if (forbidden.length > 0) {
    return `Port ${forbidden[0]} is reserved for Access Manager`;
  }
  const invalid = ports.filter((p) => p < 1 || p > 65535);
  if (invalid.length > 0) {
    return `Invalid port: ${invalid[0]} (must be 1-65535)`;
  }
  return null;
}

export function isProtectedContainer(containerId) {
  return PROTECTED_CONTAINERS.includes(containerId);
}

export function hasCriticalPorts(ports) {
  return ports.some((p) => CRITICAL_PORTS.includes(p));
}

export { CRITICAL_PORTS, FORBIDDEN_PORTS, PROTECTED_CONTAINERS };
