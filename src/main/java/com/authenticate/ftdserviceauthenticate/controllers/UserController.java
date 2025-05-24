//package com.authenticate.ftdserviceauthenticate.controllers;
//
//import com.authenticate.ftdserviceauthenticate.models.User;
//import com.authenticate.ftdserviceauthenticate.services.UserService;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//import java.util.Optional;
//import java.util.UUID;
//
//@RestController
//@RequestMapping("/auth")
//public class UserController {
//
//    private final UserService userService;
//
//    public UserController(UserService userService) {
//        this.userService = userService;
//    }
//
//    @GetMapping("/allUsers")
//    public List<User> getUsers() {
//        return userService.getAllUsers();
//    }
//
//    @GetMapping("/user/{id}")
//    public Optional<User> getUserById(@PathVariable UUID id) {
//        return userService.getUserById(id);
//    }
//
//    @GetMapping("/user/email")
//    public Optional<User> getUserByEmail(String email) {
//        return  userService.getUser(email);
//    }
//
//    @PostMapping("/signIn")
//    public User createUser(@RequestBody User user) {
//        return userService.createUser(user);
//    }
//
//    @PutMapping("/modify")
//    public User modifyUser(@RequestBody User user, UUID id) {
//        return userService.updateUser(id, user);
//    }
//
//    @PutMapping
//    public void deleteUser(@RequestBody UUID id) {
//        userService.deleteUser(id);
//    }
//}
