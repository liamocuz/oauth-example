import { useState } from "react";
import { fetchHello } from "../routes/resourceServer";

export function HelloResource() {
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const handleFetch = async () => {
    console.log("Clicked");
    setError("");
    setMessage("");
    try {
      const msg = await fetchHello();
      setMessage(msg);
    } catch (e: unknown) {
      if (e && typeof e === "object" && "message" in e) {
        setError(String((e as { message: unknown }).message));
      } else {
        setError("An unknown error occurred");
      }
    }
  };

  return (
    <div>
      <button onClick={handleFetch}>Fetch /hello</button>
      {message && <div>Message: {message}</div>}
      {error && <div style={{ color: "red" }}>{error}</div>}
    </div>
  );
}
