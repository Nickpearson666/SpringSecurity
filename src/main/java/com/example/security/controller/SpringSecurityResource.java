package com.example.security.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@RestController
public class SpringSecurityResource {

    @GetMapping("/csrf-token")
    public CsrfToken retrieveCsrfToken(HttpServletRequest request){
        return (CsrfToken) request.getAttribute("_csrf");
    }

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @PutMapping("/hello/{name}")
    @PreAuthorize("hasRole('USER') and #name == authentication.name") //role and username should match in configuration
    @PostAuthorize("returnObject.username == 'nick'") //match the return info
    public User hello(@PathVariable("name") String name){
        return new User(name);
    }
}

record User(String username){};

