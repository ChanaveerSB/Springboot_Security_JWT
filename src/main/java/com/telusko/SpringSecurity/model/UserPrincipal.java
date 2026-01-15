package com.telusko.SpringSecurity.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

//To get User Details, but it is Interface so we implement it to get class to get user details for real
//UserPrincipal : current user who is trying to access
public class UserPrincipal implements UserDetails{
    //we are implementing UserDetails Interface in UserPrincipal but we dont have username and password in UserPrincipal
    //so we can get them from Users class whose object is in MyUserDetailsService class in loadUserByUsername method

    private Users user;

    public UserPrincipal(Users user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new SimpleGrantedAuthority("USER"));
    }
    //Doubt : wt above method and its overridden content means and does
    //ChatGPT : https://chatgpt.com/share/69693856-065c-8002-a81b-779eda51b426

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
