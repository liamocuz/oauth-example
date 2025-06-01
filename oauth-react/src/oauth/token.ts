import { userManager } from "./oauth";

export async function getAccessToken() {
  const user = await userManager.getUser();
  return user?.access_token;
}