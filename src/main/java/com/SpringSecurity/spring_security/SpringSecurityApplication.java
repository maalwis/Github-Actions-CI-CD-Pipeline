package com.SpringSecurity.spring_security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {

		SpringApplication.run(SpringSecurityApplication.class, args);
		
	}

	/**
		AuthorizationFilter authorizationFilter;
		UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter;
		AuthenticationManager authenticationManager;
		ProviderManager providerManager;
		DaoAuthenticationProvider daoAuthenticationProvider;
		DefaultLoginPageGeneratingFilter defaultLoginPageGeneratingFilter;

	 */





}
