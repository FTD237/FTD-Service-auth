package com.authenticate.ftdserviceauthenticate.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
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
    @NotBlank(message = "Email can't be empty")
    @Column(unique = true)
    private String email;
    @NotBlank(message = "The password shouldn't be empty")
    @Pattern(
            regexp = "^(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "The password must contain at least 8 characters, one uppercase letter, one number and one special character."
    )

    @Column(length = 255)
    private String password;
    private Integer accountStatus = 1;
    @Column(name = "username")
    private String userName;

    public void disableAccount() {
        accountStatus = 0;
    }

}
