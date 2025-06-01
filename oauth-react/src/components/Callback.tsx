import { useEffect } from "react";
import { userManager } from "../oauth/oauth";
import { useNavigate } from "react-router";

export function Callback() {
  const navigate = useNavigate();

  useEffect(() => {
    userManager
      .signinRedirectCallback()
      .then(() => {
        navigate("/");
      })
      .catch((err) => {
        console.log(err);
        navigate("/");
      });
  }, [navigate]);

  return <div>Signing in...</div>;
}
