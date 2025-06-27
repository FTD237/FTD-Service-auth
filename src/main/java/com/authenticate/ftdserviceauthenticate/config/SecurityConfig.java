//package com.sourcing.sourcingimm.config;
//
//import com.sourcing.sourcingimm.config.Gateway.GatewayAuthenticationEntryPoint;
//import com.sourcing.sourcingimm.config.Gateway.GatewayRequestFilter;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//
//import java.util.Arrays;
//import java.util.List;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Value("${app.gateway.ip:127.0.0.1}")
//    private String gatewayIp;
//
//    @Value("${app.gateway.secret-key}")
//    private String gatewaySecretKey;
//
//    @Value("${app.gateway.header.gateway-secret:X-Gateway-Secret}")
//    private String gatewaySecretHeader;
//
//    @Bean
//    public GatewayRequestFilter gatewayRequestFilter() {
//        // Passer les valeurs au filtre
//        return new GatewayRequestFilter(gatewaySecretHeader, gatewaySecretKey, gatewayIp);
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf(AbstractHttpConfigurer::disable)
//                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
//                .authorizeHttpRequests(authz -> authz
//                        .requestMatchers(
//                                "/actuator/health",
//                                "/api/database/**"
//                        ).permitAll()
//                        .anyRequest().authenticated()
//                )
//                .sessionManagement(session -> session
//                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                )
//                .securityContext(context -> context
//                        .requireExplicitSave(false)
//                )
//                .exceptionHandling(ex -> ex
//                        .authenticationEntryPoint(new GatewayAuthenticationEntryPoint())
//                );
//
//        http.addFilterAfter(gatewayRequestFilter(), org.springframework.security.web.context.SecurityContextPersistenceFilter.class);
//
//        return http.build();
//    }
//
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(Arrays.asList(
//                "http://" + gatewayIp,
//                "http://localhost",
//                "http://127.0.0.1"
//        ));
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//        configuration.setAllowedHeaders(List.of("*"));
//        configuration.setAllowCredentials(true);
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }
//}

package com.sourcing.sourcingimm.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.gateway.ip:127.0.0.1}")
    private String gatewayIp;

    @Value("${app.gateway.secret-key}")
    private String gatewaySecretKey;

    @Value("${app.gateway.header.gateway-secret:X-Gateway-Secret}")
    private String gatewaySecretHeader;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().permitAll() // PERMET TOUT LE MONDE
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        // PAS DE FILTRES DE SÉCURITÉ

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // PERMET TOUTES LES ORIGINES
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));

        // PERMET TOUTES LES MÉTHODES
        configuration.setAllowedMethods(Arrays.asList("*"));

        // PERMET TOUS LES HEADERS
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // PERMET LES CREDENTIALS
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}