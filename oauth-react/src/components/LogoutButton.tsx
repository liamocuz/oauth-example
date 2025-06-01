import { userManager } from "../oauth/oauth";

export function LogoutButton() {
  const handleLogout = async () => {
    console.log("Logging out");
    try {
      const user = await userManager.getUser();
      if (user && user.id_token) {
        await userManager.signoutRedirect();
      }
    } catch (error) {
      console.log(error);
    }
  };
  return <button onClick={handleLogout}>Logout</button>;
}
