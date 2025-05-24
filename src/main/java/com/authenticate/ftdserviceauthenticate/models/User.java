package com.authenticate.ftdserviceauthenticate.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.util.UUID;


@Entity
@Table(name = "users")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    @Email
    @NotBlank
    private String email;
    private String password;
    private Integer accountStatus = 1;
    private String userName;

    public void disableAccount() {
        accountStatus = 0;
    }

}
