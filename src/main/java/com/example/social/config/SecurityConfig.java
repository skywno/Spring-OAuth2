package com.example.social.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.List;

@AllArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final Environment environment;
    private final String registration = "spring.security.oauth2.client.registration.";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests -> authorizeRequests
                .antMatchers("/login", "/index").permitAll()
                .anyRequest().authenticated()
        ).oauth2Login(httpSecurityOAuth2LoginConfigurer -> httpSecurityOAuth2LoginConfigurer
                .clientRegistrationRepository(clientRegistrationRepository())
                .authorizedClientService(authorizedClientService())
        );

        return http.build();
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    @Bean
    private ClientRegistrationRepository clientRegistrationRepository() {
        final List<ClientRegistration> clientRegistrations = Arrays.asList(
                googleClientRegistration(),
                facebookClientRegistration()
        );

        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }

    private ClientRegistration facebookClientRegistration() {
        final String clientId = environment.getProperty(registration + "facebook" +
                ".client-id");
        final String clientSecret = environment.getProperty(registration + "facebook" +
                ".client-secret");

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
        final String clientId = environment.getProperty(registration + "google" +
                ".client-id");
        final String clientSecret = environment.getProperty(registration + "google" +
                ".client-secret");

        return CommonOAuth2Provider
                .GOOGLE
                .getBuilder("google")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
    }

}
