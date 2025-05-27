package com.authenticate.ftdserviceauthenticate.services;

import com.authenticate.ftdserviceauthenticate.models.PasswordResetToken;
import com.authenticate.ftdserviceauthenticate.models.User;
import com.authenticate.ftdserviceauthenticate.repositories.PasswordResetTokenRepository;
import com.authenticate.ftdserviceauthenticate.repositories.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

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
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            User userEntity = userOptional.get();
            
            tokenRepository.deleteByUser(userEntity);
            String token = generateSecureToken();

            PasswordResetToken resetToken = new PasswordResetToken(token, userEntity);
            tokenRepository.save(resetToken);

            emailService.sendPasswordResetEmail(userEntity.getEmail(), token);
        }
    }

    private String generateSecureToken() {
        return UUID.randomUUID().toString();
    }

    public void resetPassword(String token, String newPassword) {
        Optional<PasswordResetToken> tokenOptional = tokenRepository.findByToken(token);

        if (tokenOptional.isEmpty()) {
            throw new IllegalArgumentException("Invalid token");
        }

        PasswordResetToken tokenEntity = tokenOptional.get();

        if (tokenEntity.isExpired()) {
            throw new IllegalArgumentException("Expired token");
        }

        if (tokenEntity.isUsed()) {
            throw new IllegalArgumentException("Token already used");
        }

        User user = tokenEntity.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        tokenEntity.setUsed(true);
        tokenRepository.save(tokenEntity);

        tokenRepository.deleteByUser(user);
    }

    public boolean isValidToken(String token) {
        Optional<PasswordResetToken> tokenOptional = tokenRepository.findByToken(token);

        if (tokenOptional.isEmpty()) {
            return false;
        }

        PasswordResetToken resetToken = tokenOptional.get();
        return !resetToken.isExpired() && !resetToken.isUsed();
    }

    @Scheduled(fixedRate = 3600000)
    public void cleanupExpiredTokens() {
        tokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
    }
}
