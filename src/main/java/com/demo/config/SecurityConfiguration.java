package com.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
	
	@Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.withUsername("employee")
            .password(passwordEncoder.encode("employee"))
            .roles("USER")
            .build();

        UserDetails admin = User.withUsername("admin")
            .password(passwordEncoder.encode("admin"))
            .roles("USER", "ADMIN")
            .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
	
	/*@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
				
        http.authorizeRequests()
        .requestMatchers("/").permitAll()
        .requestMatchers("/welcome").hasAnyRole("USER", "ADMIN")
        .requestMatchers("/getEmployees").hasAnyRole("USER", "ADMIN")
        .requestMatchers("/addNewEmployee").hasAnyRole("ADMIN")
            .anyRequest()
            .authenticated()
            .and().logout().permitAll()
            .and().formLogin(formLogin -> formLogin.loginPage("/login").permitAll());
            
        http.csrf().disable();

        return http.build();
    }*/
	
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
				
		/*http.authorizeRequests()
        .requestMatchers("/").permitAll()
        .requestMatchers("/welcome").hasAnyRole("USER", "ADMIN")
        .requestMatchers("/getEmployees").hasAnyRole("USER", "ADMIN")
        .requestMatchers("/addNewEmployee").hasAnyRole("ADMIN")
            .anyRequest()
            .authenticated()
            .and().formLogin()
            .permitAll()
            .and().logout().permitAll();*/
        
        /*http.authorizeRequests(authz -> authz
        		.requestMatchers("/login").permitAll()
                .requestMatchers("/welcome").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/getEmployees").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/addNewEmployee").hasAnyRole("ADMIN")
                .requestMatchers("/login", "/error").permitAll()
                .anyRequest().authenticated()
        );*/
		http.authorizeRequests()
		.requestMatchers("/", "/images/**", "/css/**", "/js/**", "/jsp/**").permitAll()
        .requestMatchers("/welcome").hasAnyRole("USER", "ADMIN")
        .requestMatchers("/getEmployees").hasAnyRole("USER", "ADMIN")
        .requestMatchers("/addNewEmployee").hasAnyRole("ADMIN")
            .anyRequest()
            .authenticated()
            .and().logout().permitAll();
            
            
        http.formLogin(authz -> authz
            .loginPage("/login").permitAll()
        );

        /*http.logout(authz -> authz
            .deleteCookies("JSESSIONID")
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
        );*/
        
        http.csrf().disable();

        return http.build();
    }
	
	/*@Bean
	WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.debug(false)
				.ignoring()
				.requestMatchers("/.webjars/**","/images/**","/css/**","/assets/**","/favicon.ico");
	}*/
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance(); 
	}

}
