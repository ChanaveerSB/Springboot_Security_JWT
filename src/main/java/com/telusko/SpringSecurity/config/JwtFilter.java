package com.telusko.SpringSecurity.config;

import com.telusko.SpringSecurity.service.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//we want this to behave like a filter, and we can make that happen by extending those required properties
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    //Implementing the method of OncePerRequestFilter
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //from client, we get request along with it in HEADER, we get token in form of eg : Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2ZWVyIiwiaWF0IjoxNzY4NzU5MDMxLCJleHAiOjE3Njg3NTkwNjd9.I16iF2RSr_xC13QMlCxiNQKbpXNBBxY5QFi9BxDQcYw
        //We have to extract only the Token part leaving Bearer from Header

        String authHeader = request.getHeader("Authorization"); //from request among all Headers, I only want Header that talks about Authorization. ie we get : Bearer <JWT token> but now we want only token not bearer
        //now authHeader has : Bearer <JWT token> and we only want token
        String token = null;    //By default, we will keep it as null
        //we want username as well as somewhere it will verify the token with the help of username
        String username = null;

        if(authHeader != null && authHeader.startsWith("Bearer ")) {  //authHeader.startswith("Bearer ") here "Bearer<space>"
            token = authHeader.substring(7);    //we are only taking token and skipping Bearer<space> ie 7 characters
            username = jwtService.extractUsername(token);
        }

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){

            //to do

        }

    }
}
