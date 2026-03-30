import KeycloakProvider from "next-auth/providers/keycloak";
import { prisma } from "./prisma";

export const authOptions = {
  providers: [
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_CLIENT_ID,
      clientSecret: process.env.KEYCLOAK_CLIENT_SECRET,
      issuer: process.env.KEYCLOAK_ISSUER,
    }),
  ],

  callbacks: {
    async signIn({ user }) {
      const allowed = (process.env.ADMIN_EMAILS || "")
        .split(",")
        .map((e) => e.trim().toLowerCase())
        .filter(Boolean);

      if (!allowed.includes(user.email?.toLowerCase())) {
        return false;
      }

      // Log successful sign-in
      await prisma.auditLog.create({
        data: {
          action: `Admin ${user.email} authenticated via Keycloak`,
          severity: "INFO",
          ip: null,
        },
      });

      return true;
    },

    async session({ session }) {
      // Attach user ID from database
      if (session?.user?.email) {
        const dbUser = await prisma.user.findUnique({
          where: { email: session.user.email },
        });
        if (dbUser) {
          session.user.id = dbUser.id;
          session.user.role = dbUser.role;
        }
      }
      return session;
    },
  },

  pages: {
    signIn: "/auth/signin",
    error: "/auth/error",
  },

  session: {
    strategy: "jwt",
    maxAge: (parseInt(process.env.SESSION_TIMEOUT_MINUTES) || 15) * 60,
  },
};

/**
 * Require authenticated admin session. Returns session or null.
 */
export async function requireAuth(request) {
  // Import dynamically to avoid issues with edge runtime
  const { getServerSession } = await import("next-auth");
  const session = await getServerSession(authOptions);

  if (!session?.user?.email) {
    return null;
  }

  const allowed = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);

  if (!allowed.includes(session.user.email.toLowerCase())) {
    return null;
  }

  return session;
}
