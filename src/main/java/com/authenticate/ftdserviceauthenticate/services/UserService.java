package com.authenticate.ftdserviceauthenticate.services;

import com.authenticate.ftdserviceauthenticate.models.DTOs.UserInfo;
import com.authenticate.ftdserviceauthenticate.models.User;
import com.authenticate.ftdserviceauthenticate.repositories.UserRepository;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public User getUser(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    public void saveUser(User user) {
        userRepository.save(user);
    }

    public User getUserById(UUID id) { return userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException("user not found")); }


    public UserInfo getUserInfoByEmail(String email) {
        User user = getUser(email);
        return new UserInfo(user.getId(), user.getUserName(), user.getEmail());
    }

}
