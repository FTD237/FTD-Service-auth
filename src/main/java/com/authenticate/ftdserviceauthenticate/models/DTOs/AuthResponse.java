package com.authenticate.ftdserviceauthenticate.models.DTOs;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String email;
}
