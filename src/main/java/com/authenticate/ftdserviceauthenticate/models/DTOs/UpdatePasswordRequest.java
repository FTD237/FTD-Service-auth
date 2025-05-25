package com.authenticate.ftdserviceauthenticate.models.DTOs;

import lombok.Data;

@Data
public class UpdatePasswordRequest {

    private String email;
    private String password;
    private String newPassword;
}
