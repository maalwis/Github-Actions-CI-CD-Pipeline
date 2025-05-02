package com.SpringSecurity.spring_security.config;

import com.SpringSecurity.spring_security.model.AppRole;
import com.SpringSecurity.spring_security.model.Role;
import com.SpringSecurity.spring_security.model.User;
import com.SpringSecurity.spring_security.repository.RoleRepository;
import com.SpringSecurity.spring_security.repository.UserRepository;
import com.SpringSecurity.spring_security.security.jwt.AuthEntryPointJwt;
import com.SpringSecurity.spring_security.security.jwt.AuthTokenFilter;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;


import java.time.LocalDate;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
//@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true) <-- this enables method level security.
public class SecurityConfig {

    private AuthEntryPointJwt authEntryPointJwt;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf ->
                csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers("/api/auth/public/**")
        );
        // http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests((requests) ->
                requests
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/csrf-token").permitAll()
                        .requestMatchers("/api/auth/public/**").permitAll()
                        .anyRequest().authenticated());
//         http.addFilterBefore(new CustomLoggingFilter(), UsernamePasswordAuthenticationFilter.class);
//         http.addFilterAfter(new RequestValidationFilter(), CustomLoggingFilter.class);
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPointJwt));
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository,
                                      UserRepository userRepository,
                                      PasswordEncoder passwordEncoder) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));

            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

            if (!userRepository.existsByUserName("user")) {
                User user = new User("user", "user@example.com", passwordEncoder.encode("pass"));
                user.setAccountNonLocked(false);
                user.setAccountNonExpired(true);
                user.setCredentialsNonExpired(true);
                user.setEnabled(true);
                user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user.setTwoFactorEnabled(false);
                user.setSignUpMethod("email");
                user.setRole(userRole);
                userRepository.save(user);
            }

            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin", "admin@example.com", passwordEncoder.encode("pass"));
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public UserDetailsService userDetailsService(DataSource source) {
//
//        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(source);
//
//        UserDetails user01 = User.withUsername("user1")
//                .password("{noop}pass")
//                .roles("USER")
//                .build();
//
//        UserDetails user02 =   User.withUsername("admin")
//                .password("{noop}pass")
//                .roles("ADMIN")
//                .build();
//
//        if (!manager.userExists("user1")) {
//            manager.createUser(user01);
//        }
//        if (!manager.userExists("admin")) {
//            manager.createUser(user02);
//        }
//        return manager;
//    }


}
