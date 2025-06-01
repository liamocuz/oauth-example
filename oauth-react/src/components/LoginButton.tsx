import { userManager } from "../oauth/oauth";

export function LoginButton() {
  const handleLogin = async () => {
    console.log("Logging in");
    try {
      await userManager.signinRedirect();
    } catch (error) {
      console.log(error);
    }
  };
  return <button onClick={handleLogin}>Login</button>;
}
