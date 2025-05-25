package com.authenticate.ftdserviceauthenticate.services;

import com.authenticate.ftdserviceauthenticate.models.DTOs.*;
import com.authenticate.ftdserviceauthenticate.models.User;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserAlreadyExistsException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired private UserService userService;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtService jwtService;

    public AuthResponse registerUser(RegisterRequest request) {
        if (userService.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setUserName(request.getUserName());

        userService.saveUser(user);
        String token = jwtService.generateToken(user);

        return new AuthResponse(token, user.getEmail());
    }

    public AuthResponse authenticateUser(LoginRequest request) {
        User user = userService.getUser(request.getEmail());

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Email or password incorrect");
        }

        String token = jwtService.generateToken(user);
        return new AuthResponse(token, user.getEmail());
    }

    public UserInfo validateUser(ValidateRequest request) {
        String email = jwtService.extractEmail(request.getToken());
        return userService.getUserInfoByEmail(email);
    }

    public void sendForgotPasswordRequest(ForgotPasswordRequest request) {
        User user = userService.getUser(request.getEmail());

    }


}
