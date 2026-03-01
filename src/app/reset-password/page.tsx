import { redirect } from "next/navigation";
import { AUTH_ROUTES } from "@/lib/auth/config";
import { AUTH_FRAMEWORK_CONFIG } from "@/lib/auth/framework-config";
import { ResetPasswordForm } from "@/components/auth/ResetPasswordForm";
import { UI } from "@/lib/messages";

interface ResetPasswordPageProps {
  searchParams: Promise<{ token?: string }>;
}

export default async function ResetPasswordPage({ searchParams }: ResetPasswordPageProps) {
  const { token } = await searchParams;

  // No token in URL → send to forgot-password to start the flow
  if (!token) {
    redirect(AUTH_ROUTES.forgotPassword);
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-100">
            {UI.RESET_PASSWORD_HEADING}
          </h1>
        </div>

        <ResetPasswordForm
          token={token}
          requireComplexity={AUTH_FRAMEWORK_CONFIG.security.passwordRequireComplexity}
        />
      </div>
    </div>
  );
}
