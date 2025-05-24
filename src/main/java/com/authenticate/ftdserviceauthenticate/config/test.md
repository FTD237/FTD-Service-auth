```java
// Imports nécessaires à ajouter en haut du fichier
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.BadCredentialsException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @org.springframework.beans.factory.annotation.Value("${app.gateway.ip:localhost}")
    private String gatewayIp;

    @org.springframework.beans.factory.annotation.Value("${app.gateway.secret-key}")
    private String gatewaySecretKey;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public GatewayRequestFilter gatewayRequestFilter() {
        return new GatewayRequestFilter();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/api/auth/**").permitAll() // Endpoints d'authentification
                        .anyRequest().authenticated() // Toutes autres requêtes doivent être authentifiées par la gateway
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new GatewayAuthenticationEntryPoint())
                );

        // Filtre pour valider que les requêtes viennent de la gateway
        http.addFilterBefore(gatewayRequestFilter(), BasicAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://" + gatewayIp));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

// Filtre pour valider les requêtes de la gateway
@Component
public class GatewayRequestFilter extends OncePerRequestFilter {

    @org.springframework.beans.factory.annotation.Value("${app.gateway.header.gateway-secret:X-Gateway-Secret}")
    private String gatewaySecretHeader;

    @org.springframework.beans.factory.annotation.Value("${app.gateway.secret-key}")
    private String expectedGatewaySecret;

    @org.springframework.beans.factory.annotation.Value("${app.gateway.ip:localhost}")
    private String allowedGatewayIp;

    private static final Logger logger = LoggerFactory.getLogger(GatewayRequestFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestPath = request.getRequestURI();

        // Autoriser les endpoints d'authentification publics et health check
        if (requestPath.startsWith("/api/auth/") || requestPath.equals("/actuator/health")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Valider que la requête vient de la gateway
        if (!isValidGatewayRequest(request)) {
            logger.warn("Requête non autorisée depuis l'IP: {}, Path: {}",
                    getClientIpAddress(request), requestPath);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Accès refusé - requête non autorisée\"}");
            return;
        }

        // Créer une authentification simple pour les requêtes de la gateway
        GatewayAuthentication authentication = new GatewayAuthentication();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        logger.debug("Requête validée depuis la gateway pour: {}", requestPath);
        filterChain.doFilter(request, response);
    }

    private boolean isValidGatewayRequest(HttpServletRequest request) {
        // Vérifier l'IP source
        String clientIp = getClientIpAddress(request);
        if (!allowedGatewayIp.equals(clientIp) && !"localhost".equals(allowedGatewayIp)) {
            logger.warn("IP non autorisée: {}, IP attendue: {}", clientIp, allowedGatewayIp);
            return false;
        }

        // Valider le secret partagé
        String gatewaySecret = request.getHeader(gatewaySecretHeader);
        if (!expectedGatewaySecret.equals(gatewaySecret)) {
            logger.warn("Secret gateway invalide");
            return false;
        }

        return true;
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

// Token d'authentification simple pour la gateway
public class GatewayAuthentication implements Authentication {

    private boolean authenticated = true;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList(); // Pas de gestion des rôles dans ce service
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return "gateway";
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return "gateway";
    }
}

// Point d'entrée pour les erreurs d'authentification
public class GatewayAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(GatewayAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        logger.error("Tentative d'accès non autorisée: {}", authException.getMessage());

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("error", "Non autorisé");
        errorDetails.put("message", "Accès refusé - authentification requise");
        errorDetails.put("timestamp", new Date());

        response.getWriter().write(mapper.writeValueAsString(errorDetails));
    }
}

// Contrôleur d'authentification
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody @Valid RegisterRequest registerRequest) {
        try {
            AuthResponse response = authService.registerUser(registerRequest);
            return ResponseEntity.ok(response);
        } catch (UserAlreadyExistsException e) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("L'utilisateur existe déjà", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Erreur lors de l'inscription", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody @Valid LoginRequest loginRequest) {
        try {
            AuthResponse response = authService.authenticateUser(loginRequest);
            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Identifiants invalides", "Email ou mot de passe incorrect"));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Erreur lors de la connexion", e.getMessage()));
        }
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validateUser(@RequestBody @Valid ValidateRequest validateRequest) {
        try {
            UserInfo userInfo = authService.validateUser(validateRequest);
            return ResponseEntity.ok(userInfo);
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("Utilisateur non trouvé", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Erreur lors de la validation", e.getMessage()));
        }
    }
}

// DTOs pour les requêtes
public class RegisterRequest {
    @NotBlank(message = "L'email est requis")
    @Email(message = "Format d'email invalide")
    private String email;

    @NotBlank(message = "Le mot de passe est requis")
    @Size(min = 6, message = "Le mot de passe doit contenir au moins 6 caractères")
    private String password;

    @NotBlank(message = "Le nom est requis")
    private String firstName;

    @NotBlank(message = "Le prénom est requis")
    private String lastName;

    // Getters et setters
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
}

public class LoginRequest {
    @NotBlank(message = "L'email est requis")
    @Email(message = "Format d'email invalide")
    private String email;

    @NotBlank(message = "Le mot de passe est requis")
    private String password;

    // Getters et setters
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

public class ValidateRequest {
    @NotBlank(message = "L'ID utilisateur est requis")
    private String userId;

    // Getters et setters
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
}

// DTOs pour les réponses
public class AuthResponse {
    private String userId;
    private String email;
    private String firstName;
    private String lastName;
    private String message;

    public AuthResponse(String userId, String email, String firstName, String lastName, String message) {
        this.userId = userId;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.message = message;
    }

    // Getters et setters
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}

public class UserInfo {
    private String userId;
    private String email;
    private String firstName;
    private String lastName;

    // Constructeurs, getters et setters
    public UserInfo() {}

    public UserInfo(String userId, String email, String firstName, String lastName) {
        this.userId = userId;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
}

public class ErrorResponse {
    private String error;
    private String message;
    private Date timestamp;

    public ErrorResponse(String error, String message) {
        this.error = error;
        this.message = message;
        this.timestamp = new Date();
    }

    // Getters et setters
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public Date getTimestamp() { return timestamp; }
    public void setTimestamp(Date timestamp) { this.timestamp = timestamp; }
}
```