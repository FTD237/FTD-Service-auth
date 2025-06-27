package com.authenticate.ftdserviceauthenticate.services;

import com.authenticate.ftdserviceauthenticate.models.DTOs.*;
import com.authenticate.ftdserviceauthenticate.models.User;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserAlreadyExistsException;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    @Autowired private UserService userService;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtService jwtService;
    @Autowired private EmailService emailService;

    @Transactional
    public AuthResponse registerUser(RegisterRequest request) {
        log.info("Attempting to register user with email: {}", request.getEmail());
        try {
            if (userService.existsByEmail(request.getEmail())) {
                log.warn("Registration failed - email already exists: {}", request.getEmail());
                throw new UserAlreadyExistsException("Email already exists");
            }

            User user = new User();
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setUserName(request.getUserName());

            
            userService.saveUser(user);
            String token = jwtService.generateToken(user);
//            emailService.sendNewAccountEmail(request.getEmail());
            log.info("User registered successfully: {}", request.getEmail());
            return new AuthResponse(token, user.getEmail());
        } catch (DataIntegrityViolationException e) {
            log.error("Data integrity violation for email: {}", request.getEmail(), e);
            throw new UserAlreadyExistsException(e.getMessage());
        }

    }

    @Transactional
    public AuthResponse authenticateUser(LoginRequest request) {
        User user = userService.getUser(request.getEmail());

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Email or password incorrect");
        }

        String token = jwtService.generateToken(user);
        return new AuthResponse(token, user.getEmail());
    }

    @Transactional
    public UserInfo validateUser(ValidateRequest request) {
        String email = jwtService.extractEmail(request.getToken());
        return userService.getUserInfoByEmail(email);
    }

}
