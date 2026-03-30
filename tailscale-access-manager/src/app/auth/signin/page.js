"use client";

import { signIn } from "next-auth/react";
import { useEffect } from "react";

export default function SignIn() {
  useEffect(() => {
    signIn("keycloak", { callbackUrl: "/" });
  }, []);

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh", fontFamily: "'DM Sans', sans-serif", color: "#6b7280" }}>
      Redirecting to Keycloak...
    </div>
  );
}
