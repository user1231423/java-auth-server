package com.auth.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.proc.SecurityContext;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.springframework.security.config.Customizer.withDefaults;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.UUID;

@Configuration
public class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain aSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
		http.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
		
		return http.build();
	}
	
    
	@Bean
	@Order(2)
	SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(withDefaults())
                .authorizeHttpRequests().anyRequest().authenticated();
		
		return http.build();
	}
	
	
	@Bean
	UserDetailsService userDetailsService() {
		var user1 = User.withUsername("admin")
				.password("admin")
				.roles("ADMIN")
				.authorities("openid")
				.build();
		return new InMemoryUserDetailsManager(user1);
	}
	
	
	@SuppressWarnings("deprecation")
	@Bean
	PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	@Bean
	RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client")
				.clientSecret("secret")
				.scope(OidcScopes.OPENID)
				.redirectUri("https://oidcdebugger.com/debug") // Test
				.redirectUri("https://oauthdebugger.com/debug") // Test
				.redirectUri("https://oauth.pstmn.io/v1/browser-callback") // Postman browser
				.redirectUri("https://oauth.pstmn.io/v1/callback") // Postman APP
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.build();
		
		return new InMemoryRegisteredClientRepository(registeredClient);
	}
	
	
	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
	
	@Bean
	TokenSettings tokenSetting() {
		return TokenSettings.builder().build();
	}
	
	
	@Bean
	ClientSettings clientSettings() {
		return ClientSettings.builder()
				.requireAuthorizationConsent(false)
				.requireProofKey(false)
				.build();
	}
	
	
	@Bean
	JWKSource<SecurityContext> jwkSource(){ 
		RSAKey rsaKey = generateRSA();
		JWKSet jwtSet = new JWKSet(rsaKey);
		return (jwtSelector, securityContext) -> jwtSelector.select(jwtSet);
	}
	
	public static RSAKey generateRSA() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic(); 
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}
	
	static KeyPair generateRsaKey() {
		KeyPair keyPair;
		
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}catch(Exception ex) {
			throw new IllegalStateException(ex);
		}
		
		return keyPair;
	}
}
