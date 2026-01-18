package com.telusko.SpringSecurity.service;

import com.telusko.SpringSecurity.model.Users;
import com.telusko.SpringSecurity.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepo repo;

    @Autowired
    private JWTService jwtService;

    @Autowired
    AuthenticationManager authManager;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);  //12 is strength(rounds)

    public Users register(Users user){
        user.setPassword(encoder.encode(user.getPassword()));
        return repo.save(user);
    }

    public String verify(Users user) {
        Authentication authentication =
                //authenticate method below need (unverified) Authentication object to give (verified) Authentication object to above authentication ref var but Authentication is an Interface so we use below object which is implementation class of Authentication and verifies uname and pwd by taking args
                authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));
                //eg: authenticate takes a box without a seal and verifies it and returns(provides back) sealed box if box has passed authentication
        //once we get (Authenticated/not-Authenticated user)object we can verify it(user object(eg: box) is real
        if(authentication.isAuthenticated())    //isAuthenticated() return true or false based on authentication passed or failed
//            return "Success";   //by this when user logs in we get "Success" printed but instead that we want a (JWT)Token to be generated
            //so we create a method to generate JWT token because spring does not have inbuilt method to create jwt token. So we will create a separate service class (JWTService) for JWT related as we don't want to mix Jwt related things in this or any particular role having class
            return jwtService.generateToken(user.getUsername());
        else
            return "Failed";

    }
}
