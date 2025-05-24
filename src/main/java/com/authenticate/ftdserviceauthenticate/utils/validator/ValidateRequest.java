package com.authenticate.ftdserviceauthenticate.utils.validator;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
public class ValidateRequest {

    @NotBlank(message= "ID user is required")
    private UUID userId;

    @NotBlank(message= "User email is required")
    private String email;
}
