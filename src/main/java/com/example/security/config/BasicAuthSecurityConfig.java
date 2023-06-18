package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
//
@Configuration
@EnableMethodSecurity
public class BasicAuthSecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests((req)->{
            req.requestMatchers("/users").hasRole("USER")
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest()
                    .authenticated();
        });

        httpSecurity.sessionManagement((session)->{
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });
        httpSecurity.httpBasic();
        //do not need to provide the token
        httpSecurity.csrf().disable();
        httpSecurity.headers().frameOptions().sameOrigin();
       
        return httpSecurity.build();

    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        var user = User.withUsername("nick")
//                .password("{noop}aaa") // not use any encoding
//                .roles("USER")
//                .build();
//
//        var admin = User.withUsername("jack")
//                .password("{noop}aaa")
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(user, admin);
//    }

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
