package com.example.social.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.List;

@AllArgsConstructor
@Configuration
@PropertySource("classpath:registrations.properties")
@EnableWebSecurity
public class SecurityConfig {
    private final Environment environment;
    private final String registration = "spring.security.oauth2.client.registration.";
    private final FacebookOAuth2UserService facebookOAuth2UserService;
    private final GoogleOAuth2UserService googleOAuth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests -> authorizeRequests
                .antMatchers("/login", "/index").permitAll()
                .anyRequest().authenticated()
        ).oauth2Login(httpSecurityOAuth2LoginConfigurer -> httpSecurityOAuth2LoginConfigurer
                .clientRegistrationRepository(clientRegistrationRepository())
                .authorizedClientService(authorizedClientService())
                .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                        .oidcUserService(googleOAuth2UserService) // google 인증, OpenID Connect 1.0
                        .userService(facebookOAuth2UserService)   // facebook 인증, OAuth2 통신
                )
        );

        return http.build();
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        final List<ClientRegistration> clientRegistrations = Arrays.asList(
                googleClientRegistration(),
                facebookClientRegistration()
        );

        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }

    private ClientRegistration facebookClientRegistration() {
        final String clientId = environment.getProperty("facebook.client-id");
        final String clientSecret = environment.getProperty("facebook.client-secret");

        return CommonOAuth2Provider.FACEBOOK
                .getBuilder("facebook")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .scope(
                        "public_profile",
                        "email",
                        "user_birthday",
                        "user_gender"
                )
                .build();
    }

    private ClientRegistration googleClientRegistration() {
        final String clientId = environment.getProperty("google.client-id");
        final String clientSecret = environment.getProperty("google.client-secret");

        return CommonOAuth2Provider
                .GOOGLE
                .getBuilder("google")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
    }

}
