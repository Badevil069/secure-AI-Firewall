import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/layout/Sidebar";

export const metadata: Metadata = {
  title: "Security.AI — Zero-Trust AI Firewall",
  description: "Enterprise AI Firewall for protecting AI agents from prompt injection, jailbreak attempts, credential exposure, and data exfiltration.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#06080d]">
        <Sidebar />
        <main className="ml-[260px] min-h-screen">
          {children}
        </main>
      </body>
    </html>
  );
}
