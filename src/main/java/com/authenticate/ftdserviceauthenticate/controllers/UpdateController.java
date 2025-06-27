package com.authenticate.ftdserviceauthenticate.controllers;

import com.authenticate.ftdserviceauthenticate.models.DTOs.DeleteAccountRequest;
import com.authenticate.ftdserviceauthenticate.models.DTOs.UpdatePasswordRequest;
import com.authenticate.ftdserviceauthenticate.models.DTOs.UpdateUsernameRequest;
import com.authenticate.ftdserviceauthenticate.services.UserService;
import com.authenticate.ftdserviceauthenticate.utils.ErrorResponse;
import com.authenticate.ftdserviceauthenticate.utils.exceptions.UserNotFoundException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/update")
public class UpdateController {

    @Autowired private UserService userService;

    @PutMapping("/password")
    public ResponseEntity<?> updatePassword(@RequestBody @Valid UpdatePasswordRequest updatePasswordRequest) {
        try {
            userService.updateUserPassword(updatePasswordRequest);
            return ResponseEntity.ok("Password updated successfully");
        } catch (UserNotFoundException | IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Email or password are incorrect", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal server error", e.getMessage()));
        }
    }


    @PutMapping("/username")
    public ResponseEntity<?> updateUsername(@RequestBody @Valid UpdateUsernameRequest updateUsernameRequest) {
        try {
            userService.updateUserName(updateUsernameRequest);
            return ResponseEntity.ok("Username updated successfully");

        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Email not found", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal server error", e.getMessage()));
        }
    }

    @PutMapping("/deleteAccount")
    public ResponseEntity<?> deleteAccount(@RequestBody @Valid DeleteAccountRequest deleteAccountRequest) {
        try {
            userService.deleteAccount(deleteAccountRequest);
            return ResponseEntity.ok("Account deleted successfully");
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Email not found", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal server error", e.getMessage()));
        }
    }
}
