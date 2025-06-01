package com.liamo.resourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Map;

@EnableMethodSecurity
@SpringBootApplication
public class ResourceserverApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceserverApplication.class, args);
    }

}

@Controller
@ResponseBody
class HelloController {

    @GetMapping("/hello")
    @PreAuthorize("hasAnyAuthority('SCOPE_profile', 'SCOPE_user.read')")
    public Map<String, String> hello(@AuthenticationPrincipal Jwt jwt) {
        System.out.println(jwt.getClaims());
        return Map.of("message", "Hello, " + jwt.getSubject());
    }
}

@Configuration
class SecurityConfig {
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

}
