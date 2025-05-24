package com.authenticate.ftdserviceauthenticate.utils;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
public class ErrorResponse {

    private String error;
    private String message;
    private Date timestamp;

    public ErrorResponse(String error, String message) {
        this.error = error;
        this.message = message;
        this.timestamp = new Date();
    }


}
