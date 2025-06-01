package com.liamo.authserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer configurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
            .securityMatcher(configurer.getEndpointsMatcher())
            .with(configurer, (authorizationServer) ->
                authorizationServer.oidc(Customizer.withDefaults())
            )
            .authorizeHttpRequests(request -> request.anyRequest().authenticated())
            .exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            .logout(logout -> logout
                .logoutUrl("/connect/logout")
            )
            .cors(Customizer.withDefaults());

        return http.build();
    }

    // This bean is required to permit the redirect to /login
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
        throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize
                .anyRequest().authenticated()
            )
            // Form login handles the redirect to the login page from the
            // authorization server filter chain
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("http://localhost:9090");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient react = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId("private-client")
            // If you specify a bcrypt bean, leave out {bcrypt}
            // Only set it if you want the delegating password encoder to check that part and then
            // choose the PasswordEncoder for you
            .clientSecret("$2a$10$4a5EUDE9.9ciIWO/0TofCeESoA67gzwO/yAgBn/ZeaqXYwTtVRjoC")
            // Public
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope(OidcScopes.PROFILE)
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(5))
                    .build()
            )
            .build();

        RegisteredClient authClient = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId("auth-client")
            .clientSecret("$2a$10$mNHIEZ.lN3P3pujeLbxnuek4NPGfCVNMNld3Zq/55WcihnSds3vU2")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://localhost:8084/login/oauth2/code/authClient")
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(true)
                    .build()
            )
            .scope("user.read")
            .scope(OidcScopes.OPENID)
            .build();


        RegisteredClient publicClient = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId("public-client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://localhost:8084/login/oauth2/code/public")
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(true)
                    .requireProofKey(true)
                    .build()
            )
            .scope("user.read")
            .scope(OidcScopes.OPENID)
            .build();

        RegisteredClient reactClient = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId("react-client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://localhost:9090/callback")
            .postLogoutRedirectUri("http://localhost:9090")
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(10))
                    .build()
            )
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(true)
                    .requireProofKey(true)
                    .build()
            )
            .scope("user.read")
            .scope(OidcScopes.OPENID)
            .build();

        return new InMemoryRegisteredClientRepository(react, authClient, publicClient, reactClient);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User
            .withUsername("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();
        UserDetails liam = User
            .withUsername("liam")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user, liam);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
