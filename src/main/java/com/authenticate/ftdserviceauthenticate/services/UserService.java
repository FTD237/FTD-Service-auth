package com.authenticate.ftdserviceauthenticate.services;

import com.authenticate.ftdserviceauthenticate.models.DTOs.UserInfo;
import com.authenticate.ftdserviceauthenticate.models.User;
import com.authenticate.ftdserviceauthenticate.repositories.UserRepository;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserNotFoundException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public User getUser(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    public User getUserById(UUID id) { return userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException("user not found")); }


    public UserInfo getUserInfoByEmail(String email) {
        User user = getUser(email);
        return new UserInfo(user.getId(), user.getUserName(), user.getEmail());
    }

}
