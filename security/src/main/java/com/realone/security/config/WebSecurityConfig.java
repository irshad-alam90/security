package com.realone.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.realone.security.service.JwtUserDetailsService;
import com.realone.security.util.JwtAuthenticationEntryPoint;
import com.realone.security.util.JwtAuthorizationTokenFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
	
	@Autowired
	private JwtAuthenticationEntryPoint point;
	
	@Autowired
	private JwtAuthorizationTokenFilter filter;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http.csrf(csrf -> csrf.disable())
			.cors(cors -> cors.disable())
			//.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
			//.authorizeHttpRequests()
			//.requestMatchers("/user_service/welcome","/user_service/create_user").permitAll()
			//.anyRequest()
			//.authenticated()
			//.and()
			//.authorizeHttpRequests()
			//.requestMatchers("/user_service/**").authenticated()
			//.and()
			.authorizeRequests(auth -> auth.requestMatchers("/user/auth/*","/user_service/welcome","/user_service/create_user").permitAll()
					.requestMatchers("/user_service/**").authenticated()
					.anyRequest().authenticated())
					.exceptionHandling(ex -> ex.authenticationEntryPoint(point))
					.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		
			http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
		//	.formLogin(Customizer.withDefaults());
			//.httpBasic(Customizer.withDefaults());
		return http.build();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public UserDetailsService userDetailsService() {
//		UserDetails admin = User.builder()
//				.username("irshad")
//				.password(passwordEncoder().encode("alam"))
//				.roles("ADMIN")
//				.build();
//		UserDetails user = User.builder()
//				.username("ravi")
//				.password(passwordEncoder().encode("kumar"))
//				.roles("USER")
//				.build();
				
		return new JwtUserDetailsService();
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider =  new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService());
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		return authenticationProvider;
	}
	
	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
		return builder.getAuthenticationManager();
	}
}
