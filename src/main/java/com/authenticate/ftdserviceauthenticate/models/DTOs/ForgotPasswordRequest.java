package com.authenticate.ftdserviceauthenticate.models.DTOs;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ForgotPasswordRequest {
    @Email(message = "Invalid email")
    @NotBlank(message = "Email needed")
    private String email;
}
