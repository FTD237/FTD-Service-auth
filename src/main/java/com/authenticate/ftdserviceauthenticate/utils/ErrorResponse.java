package com.authenticate.ftdserviceauthenticate.utils;

import lombok.Data;

import java.util.Date;

@Data
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
