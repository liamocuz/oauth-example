package com.liamo.authclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AuthclientApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthclientApplication.class, args);
    }

    @Bean
    RouteLocator gateway(RouteLocatorBuilder rlb) {
        return rlb.routes()
            .route("hello", rs -> rs
                .path("/hello")
                .filters(GatewayFilterSpec::tokenRelay)
                .uri("http://localhost:8082")
            )
            .route("root-redirect", rs -> rs
                .path("/")
                .filters(f -> f.redirect(302, "/hello"))
                .uri("http://localhost:8082")
            )
            .build();
    }
}
