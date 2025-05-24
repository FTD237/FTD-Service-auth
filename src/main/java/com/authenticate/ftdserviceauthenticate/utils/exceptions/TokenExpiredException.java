package com.authenticate.ftdserviceauthenticate.utils.exceptions;

public class TokenExpiredException extends  RuntimeException {

    public TokenExpiredException(String message) {
        super(message);
    }
}
