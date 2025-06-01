import { getAccessToken } from "../oauth/token";

export async function fetchHello() {
  const token = await getAccessToken();
  if (!token) {
    throw new Error("No access token found. Please log in.");
  }
  const response = await fetch("http://localhost:8082/hello", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  if (!response.ok) {
    console.log("Failed to fetch resource");
    throw new Error("Failed to fetch resource");
  }
  return response.text();
}