package com.authenticate.ftdserviceauthenticate.models.DTOs;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.UUID;

@Data
@AllArgsConstructor
public class UserInfo {
    private UUID id;
    private String userName;
    private String email;
}
