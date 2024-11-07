package com.springboot.spring_security.basicauth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class BasicSecurityConfig {

	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(
						auth -> {
							auth.anyRequest().authenticated();
						});
		
		http.sessionManagement(
						session -> 
							session.sessionCreationPolicy(
									SessionCreationPolicy.STATELESS)
						);
		
		//http.formLogin();
		http.httpBasic();
		
		http.csrf(csrf -> csrf.disable());
		
		http.headers().frameOptions().sameOrigin();
		
		//http.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));
		
		return http.build();
	}
	
//	@Bean
//	public UserDetailsService userDetails() {
//		
//		var user = User.withUsername("sri")
//				.password("{noop}pass")
//				.roles("USER")
//				.build();
//		
//		var admin = User.withUsername("admin")
//				.password("{noop}admin")
//				.roles("ADMIN")
//				.build();
//		
//		return new InMemoryUserDetailsManager(user, admin);
//	}
	
	@Bean
	public DataSource datasource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	
	@Bean
	public UserDetailsService userDetails(DataSource ds) {
		
		var user = User.withUsername("sri")
				.password("pass")
				.passwordEncoder(str -> encoder().encode(str))
				.roles("USER")
				.build();
		
		var admin = User.withUsername("admin")
				.password("admin")
				.passwordEncoder(str -> encoder().encode(str))
				.roles("ADMIN","USER")
				.build();
		
		var jdbcManager = new JdbcUserDetailsManager(ds);
		
		jdbcManager.createUser(user);
		jdbcManager.createUser(admin);
		
		return jdbcManager;
	}
	
	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
//	@Bean
//	public RSAKey rsaKey(KeyPair keyPair) {
//		
//		return new RSAKey
//				.Builder((RSAPublicKey)keyPair.getPublic())
//				.privateKey(keyPair.getPrivate())
//				.keyID(UUID.randomUUID().toString())
//				.build();
//	}
//
//	@Bean
//	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
//		var jwkSet = new JWKSet(rsaKey);
//		
//		return (jwkSelector, context) ->  jwkSelector.select(jwkSet);
//		
//	}
//	
//	@Bean
//	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
//		return NimbusJwtDecoder
//				.withPublicKey(rsaKey.toRSAPublicKey())
//				.build();
//		
//	}
//	
//	@Bean
//	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
//		return new NimbusJwtEncoder(jwkSource);
//	}
	
}
