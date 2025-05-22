package com.authenticate.ftdserviceauthenticate.services;

import com.authenticate.ftdserviceauthenticate.models.User;
import com.authenticate.ftdserviceauthenticate.repositories.UserRepository;
import jakarta.validation.constraints.Email;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public Optional<User> getUser(Email email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> getUserById(UUID id) { return userRepository.findById(id); }

    public User createUser(User user) {
        return userRepository.save(user);
    }

    public User updateUser(UUID id, User user) {
        User existingUser = userRepository.findById(id).orElse(null);
        if (existingUser != null) {
            existingUser.setEmail(user.getEmail());
            existingUser.setPassword(user.getPassword());
            return userRepository.save(existingUser);
        } else {
            return null;
        }
    }

    public void deleteUser(UUID id) {
        userRepository.findById(id).ifPresent(User::disableAccount);
    }
}
