package com.authenticate.ftdserviceauthenticate.utils.exceptions;

public class UserNotFoundException  extends  RuntimeException{

    public UserNotFoundException(String message) {
        super(message);
    }
}
