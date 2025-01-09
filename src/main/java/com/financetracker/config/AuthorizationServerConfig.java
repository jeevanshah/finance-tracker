//package com.financetracker.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//public class AuthorizationServerConfig {
//
//    // Define the authorization server settings (issuer URI)
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder()
//                .issuer("http://localhost:8080")  // Your authorization server URL
//                .build();
//    }
//
//    // Define OAuth2 clients that can interact with the authorization server
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient registeredClient = RegisteredClient.withId("my-client")
//                .clientId("my-client")
//                .clientSecret("{noop}secret")
//                .scope(OidcScopes.OPENID)  // OpenID Connect scope
//                .scope(OidcScopes.PROFILE) // Additional optional scopes like profile
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("http://localhost:3000/login/oauth2/code/my-client")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .build();
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//}
