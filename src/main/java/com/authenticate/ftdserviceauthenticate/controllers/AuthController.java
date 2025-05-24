package com.authenticate.ftdserviceauthenticate.controllers;

import com.authenticate.ftdserviceauthenticate.models.DTOs.*;
import com.authenticate.ftdserviceauthenticate.services.AuthService;
import com.authenticate.ftdserviceauthenticate.utils.ErrorResponse;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserAlreadyExistsException;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserNotFoundException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequest requestCredentials) {
        try {
            AuthResponse response = authService.registerUser(requestCredentials);
            return  ResponseEntity.ok(response);
        } catch (UserAlreadyExistsException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ErrorResponse("This user already exist", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal server error", e.getMessage()));
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticateUser(@RequestBody @Valid LoginRequest loginRequest) {
        try {
            AuthResponse response = authService.authenticateUser(loginRequest);
            return  ResponseEntity.ok(response);
        } catch (BadCredentialsException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Bad credentials", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal server error", e.getMessage()));
        }

    }

    @PostMapping("/userInfo")
    public ResponseEntity<?> getUserInfo(@RequestBody @Valid  ValidateRequest validateRequest) {
        try {
            UserInfo userInfo = authService.validateUser(validateRequest);
            return  ResponseEntity.ok(userInfo);
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("User not found", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal server error", e.getMessage()));
        }
    }
}
