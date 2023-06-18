package com.example.security.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

//@Configuration
public class JWTAuthSecurityConfig  {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests((req)->{
            req.anyRequest().authenticated();
        });

        httpSecurity.sessionManagement((session)->{
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });
        httpSecurity.httpBasic();
        //do not need to provide the token
        httpSecurity.csrf().disable();
        httpSecurity.headers().frameOptions().sameOrigin();
        httpSecurity.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return httpSecurity.build();

    }

    // Keypair->rsakey->jwksource->jwtdecoder

    @Bean
    public KeyPair keyPair(){
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }catch (Exception e){
            throw new RuntimeException();
        }
    }

    @Bean
    public RSAKey rasKey(KeyPair keyPair){
        //create key pair and create rsa key
        return new RSAKey
                .Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    @Bean
    public JWKSource jwtSource(RSAKey rsaKey){
        //create jwk source
        var jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        //configure decoder
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource jwkSource){
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
//        var user = User.withUsername("nick")
//                .password("{noop}aaa") // not use any encoding
//                .roles("USER")
//                .build();
        var user = User.withUsername("nick")
                .password("aaa")
                .passwordEncoder(str-> passwordEncoder().encode(str))
                .roles("USER")
                .build();
//        var admin = User.withUsername("jack")
//                .password("{noop}aaa")
//                .roles("ADMIN")
//                .build();
        var admin = User.withUsername("jack")
                .password("aaa")
                .passwordEncoder(str-> passwordEncoder().encode(str))
                .roles("ADMIN")
                .build();
        var jdbcUserDetails = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetails.createUser(user);
        jdbcUserDetails.createUser(admin);
        return jdbcUserDetails;
    }

    @Bean
    public DataSource dataSource(){
        //configure the data src
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
