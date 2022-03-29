/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.demo;

import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 *
 * @author Daniel
 */
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private UserService userDetailsService;
    
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
    }
    
    //El siguiente metodo es para hacer la autentiticacion del ususario
    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception{
      //auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
      //}
      auth.inMemoryAuthentication()
              .withUser("admin")
              .password("{noop}123")
              .roles("AMIN", "VENDEDOR", "USER")
              .and()
              .withUser("vendedor")
              .password("{noop}123")
              .roles("VENDEDOR", "USER")
              .and()
              .withUser("user")
              .password("{noop}123")
              .roles("USER");
    }
    
    //El siguiente metodo funciona para realizar la autorizacion de accesos
    
    @Override
    protected void configure(HttpSecurity http) throws Exception{
    http.authorizeRequests()
            .antMatchers("/crear")
            .hasRole("ADMIN")
            .antMatchers("/articulo/listado", "/categoria/listado", "/cliente/listado")
            .hasAnyRole("ADMIN", "VENDEDOR")
            .and()
            .formLogin()
            .and()
            .exceptionHandling().accessDeniedPage("/Errores/403");
    }
}
