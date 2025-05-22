package com.authenticate.ftdserviceauthenticate.repositories;

import com.authenticate.ftdserviceauthenticate.models.User;
import jakarta.validation.constraints.Email;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    boolean existsByEmail(Email email);

    Optional<User> findByEmail(Email email);

}
