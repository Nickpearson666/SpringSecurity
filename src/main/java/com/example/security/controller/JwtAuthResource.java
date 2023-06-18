package com.example.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

//@RestController
public class JwtAuthResource {

    private JwtEncoder jwtEncoder;

    public JwtAuthResource(JwtEncoder jwtEncoder){
        this.jwtEncoder = jwtEncoder;
    }

    @GetMapping("/auth")
    public JwtResponse authenticate(Authentication authentication){
        return new JwtResponse(createToken(authentication));
    }

    public String createToken(Authentication authentication){
        //create jwt token from claims
        var claims  = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60*30))
                .subject(authentication.getName())
                .claim("scope", createScope(authentication))
                .build();
        JwtEncoderParameters parameters = JwtEncoderParameters.from(claims);
        return jwtEncoder.encode(parameters).getTokenValue();
    }

    public String createScope(Authentication authentication){
        //get all the Authorities
        return authentication.getAuthorities().stream()
                .map(a->a.getAuthority())
                .collect(Collectors.joining(" "));
    }
}

record JwtResponse(String token){}
