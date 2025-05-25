package com.authenticate.ftdserviceauthenticate.models.DTOs;

import lombok.Data;

@Data
public class UpdateUsernameRequest {
    private String email;
    private String newUsername;
}
