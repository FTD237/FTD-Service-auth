package com.authenticate.ftdserviceauthenticate.models.DTOs;

import lombok.Data;

@Data
public class DeleteAccountRequest {

    private String email;
    private String password;
    private String reason;
}
