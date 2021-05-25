package com.ju.boot.springboot.config.auth;

import com.ju.boot.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAut2UserService customOAut2UserService;

    public void configure(HttpSecurity http) throws Exception{
        http.csrf().disable()
                .headers().frameOptions().disable().and()
                .authorizeRequests()
                .antMatchers("/","/css/**","/images/**"
                        ,"/js/**","/h2-console/**").permitAll()
                .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                .anyRequest().authenticated()
                .and()
                    .logout()
                        .logoutSuccessUrl("/")
                .and()
                    .oauth2Login()
                        .userInfoEndpoint()
                            .userService(customOAut2UserService);
    }
}
