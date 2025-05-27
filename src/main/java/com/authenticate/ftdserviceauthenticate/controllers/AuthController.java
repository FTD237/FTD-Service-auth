package com.authenticate.ftdserviceauthenticate.controllers;

import com.authenticate.ftdserviceauthenticate.models.DTOs.*;
import com.authenticate.ftdserviceauthenticate.services.AuthService;
import com.authenticate.ftdserviceauthenticate.services.PasswordResetService;
import com.authenticate.ftdserviceauthenticate.utils.ErrorResponse;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserAlreadyExistsException;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired private AuthService authService;
    @Autowired private PasswordResetService passwordResetService;

    // Rate limiting to avoid spam
    private final Map<String, List<Long>> requestLog = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS = 3;
    private static final long TIME_WINDOW = 900000;

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

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody @Valid ForgotPasswordRequest forgotPasswordRequest,
                                            HttpServletRequest request) {

        String clientIp = getClientIpAddress(request);

        if (!isRequestAllowed(clientIp)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("message", "Too many requests, try again later."));
        }

        try {
            passwordResetService.initiatePasswordReset(forgotPasswordRequest.getEmail());
            return ResponseEntity.ok(Map.of("message", "You will soon receive an email with a reset password link "));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        try {
            passwordResetService.resetPassword(request.getToken(), request.getNewPassword());

            return ResponseEntity.ok(Map.of(
                    "message", "Password reset successful"
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/validate-reset-token")
    public ResponseEntity<?> validateResetToken(@RequestBody String token) {
        boolean isValid = passwordResetService.isValidToken(token);

        if (isValid) {
            return ResponseEntity.ok(Map.of("valid", true));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("valid", false, "message", "Expired or invalid token"));
        }
    }

    private boolean isRequestAllowed(String clientIp) {
        long now = System.currentTimeMillis();

        requestLog.compute(clientIp, (ip, timestamps) -> {
            if (timestamps == null) {
                timestamps = new ArrayList<>();
            }

            timestamps.removeIf(timestamp -> now - timestamp > TIME_WINDOW);

            if (timestamps.size() < MAX_REQUESTS) {
                timestamps.add(now);
                return timestamps;
            }

            return timestamps;
        });

        return requestLog.get(clientIp).size() <= MAX_REQUESTS;

    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor == null) {
            return request.getRemoteAddr();
        } else {
            return xForwardedFor.split(",")[0];
        }
    }

}
