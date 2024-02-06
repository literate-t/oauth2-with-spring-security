package io.security.oauth2withspringsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ClientConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(
            (requests) -> requests.antMatchers("/login").permitAll().anyRequest().authenticated());
        http.oauth2Login(oauth2 -> oauth2.loginPage("/login")
            .authorizationEndpoint(
                authorizationEndpointConfig -> authorizationEndpointConfig.baseUri(
                    "/oauth2/v1/authorization")) // "/oauth2/authorization" -> default
            .redirectionEndpoint(redirectionEndpointConfig -> redirectionEndpointConfig.baseUri(
                // yml 파일에도 반영되어야 하고 인가서버에도 반영되어야 함
                "/login/v1/oauth2/code/*")) // "/login/oauth2/code/*" -> default
        );

        return http.build();
    }

    // oidcLogoutSuccessHandler
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests(
//            authRequest -> authRequest.anyRequest().authenticated());
//        http.oauth2Login(Customizer.withDefaults());
//        http.logout()
//            .logoutSuccessHandler(oidcLogoutSuccessHandler())
//            .invalidateHttpSession(true)
//            .clearAuthentication(true)
//            .deleteCookies("JSESSIONID");
//
//        return http.build();
//    }
//    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
//        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(
//            clientRegistrationRepository);
//
//        successHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
//
//        return successHandler;
//    }
}
