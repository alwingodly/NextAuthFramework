import { auth } from "@/auth";
import { redirect } from "next/navigation";
import { AUTH_ROUTES } from "@/lib/auth/config";
import { Role } from "@/generated/prisma/enums";

export default async function Home() {
  const session = await auth();

  if (!session?.user) redirect(AUTH_ROUTES.login);

  if (session.user.role === Role.ADMIN) {
    redirect(AUTH_ROUTES.adminHome);
  }

  redirect(AUTH_ROUTES.userHome);
}
