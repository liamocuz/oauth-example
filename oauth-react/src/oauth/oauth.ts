import {
  UserManager,
  WebStorageStateStore,
  type UserManagerSettings,
} from "oidc-client-ts";

const oidcConfig: UserManagerSettings = {
  authority: "http://localhost:8080",
  client_id: "react-client",
  redirect_uri: window.location.origin + "/callback",
  response_type: "code",
  scope: "openid",
  post_logout_redirect_uri: window.location.origin,
  stateStore: new WebStorageStateStore({ store: window.localStorage }),
  automaticSilentRenew: false,
  silent_redirect_uri: undefined,
};

export const userManager = new UserManager(oidcConfig);
userManager.events.addAccessTokenExpiring(() => {
  console.log("Expiring");
});
userManager.events.addAccessTokenExpired(() => {
  console.log("Expired");
});
