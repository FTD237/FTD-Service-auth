```java
// 1. Entity - PasswordResetToken.java
@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String token;
    
    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;
    
    @Column(nullable = false)
    private LocalDateTime expiryDate;
    
    @Column(nullable = false)
    private boolean used = false;
    
    public PasswordResetToken() {}
    
    public PasswordResetToken(String token, User user) {
        this.token = token;
        this.user = user;
        this.expiryDate = LocalDateTime.now().plusMinutes(30); // Expire dans 30 min
    }
    
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiryDate);
    }
    
    // Getters et setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    
    public LocalDateTime getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDateTime expiryDate) { this.expiryDate = expiryDate; }
    
    public boolean isUsed() { return used; }
    public void setUsed(boolean used) { this.used = used; }
}

// 2. Repository - PasswordResetTokenRepository.java
@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
    void deleteByUser(User user);
    void deleteByExpiryDateBefore(LocalDateTime now);
}

// 3. DTO - ForgotPasswordRequest.java
public class ForgotPasswordRequest {
    @Email(message = "Email invalide")
    @NotBlank(message = "Email requis")
    private String email;
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}

// 4. DTO - ResetPasswordRequest.java
public class ResetPasswordRequest {
    @NotBlank(message = "Token requis")
    private String token;
    
    @NotBlank(message = "Mot de passe requis")
    @Size(min = 8, message = "Le mot de passe doit contenir au moins 8 caractères")
    private String newPassword;
    
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    
    public String getNewPassword() { return newPassword; }
    public void setNewPassword(String newPassword) { this.newPassword = newPassword; }
}

// 5. Service - PasswordResetService.java
@Service
@Transactional
public class PasswordResetService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordResetTokenRepository tokenRepository;
    
    @Autowired
    private EmailService emailService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public void initiatePasswordReset(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            
            // Supprimer les anciens tokens pour cet utilisateur
            tokenRepository.deleteByUser(user);
            
            // Générer un nouveau token
            String token = generateSecureToken();
            
            // Créer et sauvegarder le token
            PasswordResetToken resetToken = new PasswordResetToken(token, user);
            tokenRepository.save(resetToken);
            
            // Envoyer l'email
            emailService.sendPasswordResetEmail(user.getEmail(), token);
        }
        
        // Ne pas révéler si l'email existe ou non pour des raisons de sécurité
        // On retourne toujours une réponse positive
    }
    
    public void resetPassword(String token, String newPassword) {
        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByToken(token);
        
        if (tokenOpt.isEmpty()) {
            throw new IllegalArgumentException("Token invalide");
        }
        
        PasswordResetToken resetToken = tokenOpt.get();
        
        if (resetToken.isExpired()) {
            throw new IllegalArgumentException("Token expiré");
        }
        
        if (resetToken.isUsed()) {
            throw new IllegalArgumentException("Token déjà utilisé");
        }
        
        // Mettre à jour le mot de passe
        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        
        // Marquer le token comme utilisé
        resetToken.setUsed(true);
        tokenRepository.save(resetToken);
        
        // Optionnel : supprimer tous les tokens pour cet utilisateur
        tokenRepository.deleteByUser(user);
    }
    
    public boolean isValidToken(String token) {
        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByToken(token);
        
        if (tokenOpt.isEmpty()) {
            return false;
        }
        
        PasswordResetToken resetToken = tokenOpt.get();
        return !resetToken.isExpired() && !resetToken.isUsed();
    }
    
    private String generateSecureToken() {
        return UUID.randomUUID().toString();
    }
    
    // Méthode pour nettoyer les tokens expirés (à appeler périodiquement)
    @Scheduled(fixedRate = 3600000) // Toutes les heures
    public void cleanupExpiredTokens() {
        tokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
    }
}

// 6. Service - EmailService.java
@Service
public class EmailService {
    
    @Autowired
    private JavaMailSender mailSender;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    public void sendPasswordResetEmail(String email, String token) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            
            helper.setTo(email);
            helper.setSubject("Réinitialisation de votre mot de passe");
            
            String resetUrl = frontendUrl + "/reset-password?token=" + token;
            
            String htmlContent = buildEmailContent(resetUrl);
            helper.setText(htmlContent, true);
            
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Erreur lors de l'envoi de l'email", e);
        }
    }
    
    private String buildEmailContent(String resetUrl) {
        return "<html>" +
                "<body>" +
                "<h2>Réinitialisation de mot de passe</h2>" +
                "<p>Vous avez demandé une réinitialisation de votre mot de passe.</p>" +
                "<p>Cliquez sur le lien ci-dessous pour définir un nouveau mot de passe :</p>" +
                "<a href='" + resetUrl + "' style='background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Réinitialiser le mot de passe</a>" +
                "<p>Ce lien expire dans 30 minutes.</p>" +
                "<p>Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.</p>" +
                "</body>" +
                "</html>";
    }
}

// 7. Controller - AuthController.java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private PasswordResetService passwordResetService;
    
    // Rate limiting pour éviter le spam
    private final Map<String, List<Long>> requestLog = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS = 3;
    private static final long TIME_WINDOW = 900000; // 15 minutes
    
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
                                          HttpServletRequest httpRequest) {
        
        String clientIp = getClientIpAddress(httpRequest);
        
        // Vérifier le rate limiting
        if (!isRequestAllowed(clientIp)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("message", "Trop de tentatives. Réessayez plus tard."));
        }
        
        try {
            passwordResetService.initiatePasswordReset(request.getEmail());
            
            return ResponseEntity.ok(Map.of(
                    "message", "Si cette adresse email existe, vous recevrez un lien de réinitialisation."
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Une erreur est survenue"));
        }
    }
    
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            passwordResetService.resetPassword(request.getToken(), request.getNewPassword());
            
            return ResponseEntity.ok(Map.of(
                    "message", "Mot de passe réinitialisé avec succès"
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Une erreur est survenue"));
        }
    }
    
    @GetMapping("/validate-reset-token")
    public ResponseEntity<?> validateResetToken(@RequestParam String token) {
        boolean isValid = passwordResetService.isValidToken(token);
        
        if (isValid) {
            return ResponseEntity.ok(Map.of("valid", true));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("valid", false, "message", "Token invalide ou expiré"));
        }
    }
    
    private boolean isRequestAllowed(String clientIp) {
        long now = System.currentTimeMillis();
        
        requestLog.compute(clientIp, (ip, timestamps) -> {
            if (timestamps == null) {
                timestamps = new ArrayList<>();
            }
            
            // Supprimer les anciens timestamps
            timestamps.removeIf(timestamp -> now - timestamp > TIME_WINDOW);
            
            // Vérifier si on peut ajouter une nouvelle requête
            if (timestamps.size() < MAX_REQUESTS) {
                timestamps.add(now);
                return timestamps;
            }
            
            return timestamps;
        });
        
        return requestLog.get(clientIp).size() <= MAX_REQUESTS;
    }
    
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader == null) {
            return request.getRemoteAddr();
        } else {
            return xForwardedForHeader.split(",")[0];
        }
    }
}

// 8. Configuration - application.yml
/*
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/your_db
    username: your_username
    password: your_password
    driver-class-name: com.mysql.cj.jdbc.Driver
  
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
  
  mail:
    host: smtp.gmail.com
    port: 587
    username: your-email@gmail.com
    password: your-app-password
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true

app:
  frontend:
    url: http://localhost:3000

logging:
  level:
    com.yourpackage: DEBUG
*/
```