package com.telusko.SpringSecurity.config;

import com.telusko.SpringSecurity.service.JWTService;
import com.telusko.SpringSecurity.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//we want this to behave like a filter, and we can make that happen by extending those required properties
@Component
public class JwtFilter extends OncePerRequestFilter {

//    @Autowired
//    private JWTService jwtService;
//
//    @Autowired
//    ApplicationContext context;  //to get the bean of UserDetails

    //reading above @Autowired lines IntelliJ IDEA is giving warning “Field injection is not recommended” because of following reasons :

//        Spring allows field injection, but:
//        ❌ Hard to test (cannot create object without Spring)
//        ❌ Hidden dependencies
//        ❌ Breaks immutability
//        ❌ Not recommended by Spring team
//        So IDE (IntelliJ / STS) shows a warning, not a compile/runtime error.

    private final JWTService jwtService;
    private final ApplicationContext context;

    @Autowired
    public JwtFilter(JWTService jwtService, ApplicationContext context) {
        this.jwtService = jwtService;
        this.context = context;
    }
    //In Spring Boot 2.4+, if a class has only one constructor, Spring automatically uses it for dependency injection without @Autowired.
    //Spring itself creates the JwtFilter object and supplies the constructor parameters from existing beans, so you never create it manually or pass dependencies using new.


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
            UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(username); //it will give empty object but we need object with data
            //To validate we have to do 2 things one is that the token should be validated and second is that the username should be part of the database so we pass object(reference) of userDetails object
            if(jwtService.validateToken(token, userDetails)){
                //now after validating token and as it is valid and execute the if block
                //Now token is valid so we have to amke next filter work ie UsernamePasswordFiler
                //we will pass token instead of filter
                //this token asks 3 things (1.principal 2.credentials 3.autorities) in constructor
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

                //the authToken knows about the user but, it should also know about request object (from method signature) , As request object have lots of data
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
                //by doing ^this we are adding the token to the chain
            }
        }
        filterChain.doFilter(request,response);
    }
}
