package com.authenticate.ftdserviceauthenticate.services;

import com.authenticate.ftdserviceauthenticate.models.DTOs.*;
import com.authenticate.ftdserviceauthenticate.models.User;
import com.authenticate.ftdserviceauthenticate.repositories.UserRepository;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

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

    public UserInfo getUserInfoByEmail(String email) {
        User user = getUser(email);
        return new UserInfo(user.getId(), user.getUserName(), user.getEmail());
    }


    public void updateUserPassword(UpdatePasswordRequest request) {
        User user = getUser(request.getEmail());

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) throw new BadCredentialsException("password incorrect");

        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);
    }

    public void updateUserName(UpdateUsernameRequest request) {
        User user = getUser(request.getEmail());

        user.setUserName(request.getNewUsername());
    }

    public void deleteAccount(DeleteAccountRequest request) {
        User user = getUser(request.getEmail());


        if (passwordEncoder.matches(request.getPassword(), user.getPassword())) user.disableAccount();
    }
}
