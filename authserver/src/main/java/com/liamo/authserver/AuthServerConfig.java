package com.liamo.authserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@Configuration
public class AuthServerConfig {

    Map<String, String> issuerToIdp = Map.of(
        "https://accounts.google.com", "Google",
        "http://localhost", "local"
    );

    @Bean
    @Order(1)
    public SecurityFilterChain oauthSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer configurer = new OAuth2AuthorizationServerConfigurer();

        http
            .securityMatcher(configurer.getEndpointsMatcher())
            .with(configurer, (as) -> as.oidc(Customizer.withDefaults()))
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
            .cors(Customizer.withDefaults())
            .exceptionHandling(exception -> exception
                // This is the important line: redirect to /signin for HTML requests
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/signin"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/signin", "/css/**", "/js/**", "/images/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/signin")
                .loginProcessingUrl("/login")
                .permitAll()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/signin")
            )
            .cors(Customizer.withDefaults());

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
        RegisteredClient privateClient = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId("private-client")
            // If you specify a bcrypt bean, leave out {bcrypt}
            // Only set it if you want the delegating password encoder to check that part and then
            // choose the PasswordEncoder for you
            .clientSecret("$2a$10$FZuFf9bcmF9ZSgl4HG3a4OftWzX/laUiwJb/niqVftaIFM/l02RQe")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("user.read")
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(5))
                    .build()
            )
            .build();

        // Spring boot auth client
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

        // React SPA frontend
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
            .scope(OidcScopes.OPENID)
            .build();

        return new InMemoryRegisteredClientRepository(
            privateClient, authClient, publicClient, reactClient
        );
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User
            .withUsername("user@gmail.com")
            .password(passwordEncoder().encode("password"))
            .roles("user.read")
            .build();
        UserDetails google = User
            .withUsername("###_Google")
            .password(passwordEncoder().encode("password")) // redundant
            .roles("user.read")
            .build();
        UserDetails bob = User
            .withUsername("bob")
            .password(passwordEncoder().encode("seaotter"))
            .roles("user.read")
            .build();
        return new InMemoryUserDetailsManager(user, google, bob);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // This adds the custom "roles" claim to the jwt
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            String email = "";
            String firstName = "";
            UserDetails userDetails = null;

            Authentication principal = context.getPrincipal();
            if (principal instanceof OAuth2ClientAuthenticationToken clientToken) {
                System.out.println("Client token");
                System.out.println(clientToken);
                return;
            }

            if (principal instanceof OAuth2AuthenticationToken oauth) {
                System.out.println("OAuth");
                System.out.println(oauth);

                OAuth2User oAuth2User = oauth.getPrincipal();

                email = oAuth2User.getAttribute("email");
                String iss = oAuth2User.getAttribute("iss").toString();
                String idpName = issuerToIdp.get(iss);

                firstName = oAuth2User.getAttribute("given_name") + " from Google";

                String username = oauth.getName() + "_" + idpName;
                userDetails = userDetailsService().loadUserByUsername(username);

            } else if (principal instanceof UsernamePasswordAuthenticationToken token){
                System.out.println("Token");
                System.out.println(token);

                userDetails = (User) token.getPrincipal();

                firstName = "User from AuthServer";
                email = userDetails.getUsername();
            }

            var roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).toList();
            context.getClaims().claim("roles", roles);
            context.getClaims().claim("email", email);
            context.getClaims().claim("first_name", firstName);
        };
    }
}
