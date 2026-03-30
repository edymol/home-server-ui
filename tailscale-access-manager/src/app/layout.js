import "./globals.css";
import Providers from "./providers";

export const metadata = {
  title: "Access Manager — Tailscale ACL Control",
  description: "Security-first ACL management for Proxmox cluster",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
