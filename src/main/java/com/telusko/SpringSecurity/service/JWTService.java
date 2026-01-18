package com.telusko.SpringSecurity.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JWTService {

    private String secretKey = "" ;

//    public JWTService(){
//        //We can write below try catch code from this constructor inside the starting of getKey method (present at last in this class)
//        try {
//            //KeyGenerator is in javax.crypto package
//            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");   //this might throw an exception but this is in constructor so we cover with try catch
//            SecretKey sk = keyGen.generateKey();    //keyGen.generateKey() this method will generate key but gives in SecretKey Type.
//            secretKey = Base64.getEncoder().encodeToString(sk.getEncoded());    //converts sk into string type as required
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//    }


    public String generateToken(String username) {
        //random token from jwt website to test
//        return "xyzakfguilawgiughvvriqoh3.goicu4ionyaoctynulyrcguvnyyatlwuoeeeopqouahfucuancuxeuzbusg.fruaguibeufhuehaghbokooamkneutegfhbbv";
        //But we don't want it(because it's Invalid).and all users cant have same token as it will be a biggest security issue.
        //We want each one user to have unique JWT token.

        //token should have CLAIMS (what user is claims) subject (ie username), issue date, expiry date etc... So where will u keep all these things
        //So we create Map of Claims and type of this Map (HashMap) will be String(key) and Object(value) because value will differ
        Map<String, Object> claims = new HashMap<>();
        //now we have to return the token : Jwts class (it belongs io.jsonwebtoken package which we have got from Maven Repository
        // this Jwts class has already inbuild methods like "claims" (where we mention all the claims) and "claimBuilder" (so we basically use this method to build our claims)
        return Jwts.builder()
                .claims()
                .add(claims) //in the above map it will add all the claims mention next(ie below)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 60 * 60 * 10))    //currentTimeMillis() provides time "+" means from current time in Milliseconds so * 60 is seconds And *60 is minutes and * 10 is 10 minutes. So this token will be applicable for only 10 minutes
                .and()  //now we have to add sign ie Data Signature, but it's (.signWith() method) not showing/there now so we first use .and()
                .signWith(getKey()) //we have to generate a key here and pass it.Sinse we don't want to write lines of code to generate key in within this () so create a method
                .compact();  //this will generate a token for u

    }

//    private Key getKey() {
//        byte[] keyBytes = Decoders.BASE64.decode(secretKey);    //Keys.hmacShaKeyFor() takes in bytes so we convert String (secretKey) in bytes then pass to Keys.hmacShaKeyFor() which returns secretKey in bytes as Key object type
//        return Keys.hmacShaKeyFor(keyBytes);   //As secretKey is String, and we need Key type object to be returned. So we use Keys.hmacShaKeyFor() ,but it takes in bytes so we convert String in bytes then pass to Keys.hmacShaKeyFor() which returns secretKey in bytes as Key object type
//    }

    //or

    private Key getKey() {
        //KeyGenerator is in javax.crypto package
        try {
            //KeyGenerator is in javax.crypto package
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");   //this might throw an exception
            //We used try catch because if we use throws in method signature then it will pass to method call(line no 63) and that will pass to its method call(UserService class - line no 40). Thus, we used try catch here itself so not throw the exception to all method call chains
            SecretKey sk = keyGen.generateKey();    //keyGen.generateKey() this method will generate key but gives in SecretKey Type.
            secretKey = Base64.getEncoder().encodeToString(sk.getEncoded());    //converts sk into string type as required
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);    //Keys.hmacShaKeyFor() takes in bytes so we convert String (secretKey) in bytes then pass to Keys.hmacShaKeyFor() which returns secretKey in bytes as Key object type
        return Keys.hmacShaKeyFor(keyBytes);   //As secretKey is String, and we need Key type object to be returned. So we use Keys.hmacShaKeyFor() ,but it takes in bytes so we convert String in bytes then pass to Keys.hmacShaKeyFor() which returns secretKey in bytes as Key object type
    }

    //run the SpringSecurityApplication go to postman select POST option and use "localhost:8080/login" and select in authorization(auth) as no-auth option and go to body and write username and password from the existing DB users table and click on send
    //we will get a token, then go to jwt.io website there paste the token on (left side) Encoded value side, we will get the claims on (right side) Decode payload
    //now we are logged in so we don't want to send get request of all students with username and password instead we want to send get request GET "localhost:8080/students" along with that (above lines ^ way) generated jwt token copying and pasting (passing) in Auth - type - Bearer Token  (in token box)
    //but it's not showing students even after sending token because still we have to VALIDATE the jwt token we sent (through postmen)
    //Generating Token done . Validating Token Remains :

    //In SecurityConfig class line no 77, the default authentication used for all requests except "register" and "login" is UserPasswordAuthentication (UPA), So we have to place our JWT filter in first place and place this (UPA) uname and pwd checking filter after JWT filter
    //If Jwt validates that the user is logged in then it confirms UPA filter that I have already Authenticated this user using their JWT Token (ie they are logged in) so u can continue the other works
    //that means we have to add JWT filter before UPA filter. So we will make changes in SecurityConfig class to add Jwt filter before the UPA filter

    public String extractUsername(String token) {
        return "";
    }
}
