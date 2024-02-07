package io.security.oauth2withspringsecurity.config;

import io.security.oauth2withspringsecurity.filter.CustomOAuth2AuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class OAuth2ClientConfig {

    private final DefaultOAuth2AuthorizedClientManager defaultOAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientRepository clientRepository;

    public OAuth2ClientConfig(
        DefaultOAuth2AuthorizedClientManager defaultOAuth2AuthorizedClientManager,
        OAuth2AuthorizedClientRepository clientRepository) {

        this.defaultOAuth2AuthorizedClientManager = defaultOAuth2AuthorizedClientManager;
        this.clientRepository = clientRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/", "/client", "/oauth2LoginWithPassword", "/logout",
                "/oauth2LoginClientCredentials").permitAll()
            .anyRequest()
            .authenticated().and()
//            .oauth2Login(Customizer.withDefaults())   // 인가, 인증처리 다 해준다
            .oauth2Client(Customizer.withDefaults()); // 인가까지만 처리해주고 인증처리까지 해주지 않는다

        // 필터 등록을 하면 LoginController는 호출되지 않음
        http.addFilterBefore(customOAuth2AuthenticationFilter(),
            UsernamePasswordAuthenticationFilter.class);
//        다음과 같이 처리하면 커스텀 필터에서 authenticaion 객체의 null 처리를 하지 않아도 된다
//        http.addFilterAfter(customOAuth2AuthenticationFilter(),
//            AnonymousAuthenticationFilter.class);

        return http.build();
    }

    private CustomOAuth2AuthenticationFilter customOAuth2AuthenticationFilter() {
        CustomOAuth2AuthenticationFilter authenticationFilter = new CustomOAuth2AuthenticationFilter(
            defaultOAuth2AuthorizedClientManager, clientRepository);

        authenticationFilter.setAuthenticationSuccessHandler(
            (request, response, authentication) -> {
                response.sendRedirect("/home");
            });

        return authenticationFilter;
    }

//    private final ClientRegistrationRepository clientRegistrationRepository;
//
//    public OAuth2ClientConfig(ClientRegistrationRepository clientRegistrationRepository) {
//        this.clientRegistrationRepository = clientRegistrationRepository;
//    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests(
//            (requests) -> requests.antMatchers("/home").permitAll().anyRequest().authenticated());
//        http.oauth2Login(
//            httpSecurityOAuth2LoginConfigurer -> httpSecurityOAuth2LoginConfigurer.authorizationEndpoint(
//                authorizationEndpointConfig -> authorizationEndpointConfig.authorizationRequestResolver(
//                    customResolver())));
//        http.logout().logoutSuccessUrl("/home");
//
//        return http.build();
//    }

//    private OAuth2AuthorizationRequestResolver customResolver() {
//        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
//            "/oauth2/authorization");
//    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests(
//            (requests) -> requests.antMatchers("/login").permitAll().anyRequest().authenticated());
//        http.oauth2Login(oauth2 -> oauth2.loginPage("/login")
//            .authorizationEndpoint(
//                authorizationEndpointConfig -> authorizationEndpointConfig.baseUri(
//                    "/oauth2/v1/authorization")) // "/oauth2/authorization" -> default
//            .redirectionEndpoint(redirectionEndpointConfig -> redirectionEndpointConfig.baseUri(
//                // yml 파일에도 반영되어야 하고 인가서버에도 반영되어야 함
//                "/login/v1/oauth2/code/*")) // "/login/oauth2/code/*" -> default
//        );
//
//        return http.build();
//    }

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
