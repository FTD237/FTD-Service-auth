package com.authenticate.ftdserviceauthenticate.repositories;

import com.authenticate.ftdserviceauthenticate.models.PasswordResetToken;
import com.authenticate.ftdserviceauthenticate.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
    void deleteByUser(User user);
    void deleteByExpiryDateBefore(LocalDateTime now);

}
