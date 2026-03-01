import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { AUTH_ROUTES } from "@/lib/auth/config";
import { Role } from "@/generated/prisma/enums";
import { ForgotPasswordForm } from "@/components/auth/ForgotPasswordForm";
import { UI } from "@/lib/messages";

export default async function ForgotPasswordPage() {
  // Already logged in → no need for a reset
  const session = await auth();
  if (session?.user) {
    redirect(
      session.user.role === Role.ADMIN
        ? AUTH_ROUTES.adminHome
        : AUTH_ROUTES.userHome
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-100">
            {UI.FORGOT_PASSWORD_HEADING}
          </h1>
          <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
            {UI.FORGOT_PASSWORD_SUBHEADING}
          </p>
        </div>

        <ForgotPasswordForm />
      </div>
    </div>
  );
}
