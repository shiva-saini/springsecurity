package com.security.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {


    // @Bean is used to return object of this function
    // PasswordEncoder will take password and bcrypt it
    @Bean
    public PasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(){
      // this is authenticate the user with valid username and password
        // here UserDetailsService is parent class that's why we are able to return child class(InMemoryUserDetailsManager)
//       //  object
        UserDetails student = User.withUsername("student1")
                .password(getPasswordEncoder().encode("student"))
                .roles("STUDENT")
                .build();

        UserDetails teacher = User.withUsername("teacher1")
                .password(getPasswordEncoder().encode("teacher"))
                .roles("TEACHER")
                .build();

        return new InMemoryUserDetailsManager(student,teacher);

    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
         // this will help to authorize the user that what all end points that a user can use
        http.csrf().disable()
                .authorizeHttpRequests()
                .antMatchers("/visitor/**")
                .permitAll()
                .antMatchers("/student/**")
                .hasRole("STUDENT")
                .antMatchers("/teacher/**")
                .hasRole("TEACHER")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();

        return http.build();
    }
}