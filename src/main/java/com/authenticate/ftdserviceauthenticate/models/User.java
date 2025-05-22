package com.authenticate.ftdserviceauthenticate.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;

import java.util.UUID;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    private Email email;
    private String password;
    private Integer accountStatus;

    public User() {}

    public User(Email email, String password) {
        this.email = email;
        this.password = password;
        this.accountStatus = 1;
    }

    public UUID getId() {
        return id;
    }

    public void setEmail(Email email) {
        this.email = email;
    }

    public Email getEmail() {
        return email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public Integer getAccountStatus() {
        return accountStatus;
    }

    public void disableAccount() {
        accountStatus = 0;
    }

}
