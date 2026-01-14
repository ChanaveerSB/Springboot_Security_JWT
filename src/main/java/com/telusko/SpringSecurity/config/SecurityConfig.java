package com.telusko.SpringSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity //don't go with default flow go with below flow
public class SecurityConfig {
    //bean for security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {  //HttpSecurity gives SecurityFilterChain object
        //http.build() gives SecurityFilterChain
        return http.build();
    }


}
