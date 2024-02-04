package io.security.oauth2withspringsecurity;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    public IndexController(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }


    @GetMapping("/")
    public String index() {
        return "index";
    }

    // OAuth2
    @GetMapping("/user")
    public OAuth2User user(String accessToken) {
        ClientRegistration keycloakRegistration = clientRegistrationRepository.findByRegistrationId(
            "keycloak");

        OAuth2AccessToken token = new OAuth2AccessToken(TokenType.BEARER, accessToken,
            Instant.now(), Instant.MAX);
        OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(keycloakRegistration, token);
        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();

        return defaultOAuth2UserService.loadUser(oAuth2UserRequest);
    }

    // OIDC
    @GetMapping("/oidc")
    public OAuth2User user(String accessToken, String idToken) {
        ClientRegistration keycloakRegistration = clientRegistrationRepository.findByRegistrationId(
            "keycloak");

        OAuth2AccessToken token = new OAuth2AccessToken(TokenType.BEARER, accessToken,
            Instant.now(), Instant.MAX);
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(IdTokenClaimNames.ISS, "http://localhost:8080/realms/oauth2");
        idTokenClaims.put(IdTokenClaimNames.SUB, "OIDC0");
        idTokenClaims.put("preferred_username", "user");

        OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.now(), Instant.MAX,
            idTokenClaims);

        OidcUserRequest oidcUserRequest = new OidcUserRequest(keycloakRegistration, token,
            oidcIdToken);
        OidcUserService oidcUserService = new OidcUserService();

        return oidcUserService.loadUser(oidcUserRequest);
    }
}
