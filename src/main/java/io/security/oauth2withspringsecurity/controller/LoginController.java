package io.security.oauth2withspringsecurity.controller;

import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    private final Duration clockSkew = Duration.ofSeconds(3600);

    private final Clock clock = Clock.systemUTC();


    // AppConfig에 정의되어 있음
    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    public LoginController(DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
        OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
        this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
        this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;
    }

    @GetMapping("/oauth2LoginWithPassword")
    public String oauth2LoginWithPassword(Model model, HttpServletRequest request,
        HttpServletResponse response) {

        // Anonymous
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(
                "keycloak").principal(authentication)
            .attribute(HttpServletRequest.class.getName(), request)
            .attribute(HttpServletResponse.class.getName(), response).build();

        OAuth2AuthorizedClient auth2AuthorizedClient = oAuth2AuthorizedClientManager.authorize(
            authorizeRequest);

        if (null != auth2AuthorizedClient) {
            // 권한 부여 방식을 변경하지 않고 실행(refresh token
            // 액세스 토큰 만료 && 리프레시 토큰 존재면 RefreshTokenOAuth2AuthorizedClientProvider으로 가게 함
            // 아래 방식보다 코드가 간단함
//            if (hasTokenExpired(auth2AuthorizedClient.getAccessToken())
//                && null != auth2AuthorizedClient.getRefreshToken()) {
//                oAuth2AuthorizedClientManager.authorize(authorizeRequest);
//            }

            // 권한 부여 방식을 변경하고 실행(refresh token)
            // DelegatingOAuth2AuthorizedClientProvider.authorize에서
            // 바로 RefreshTokenOAuth2AuthorizedClientProvider을 실행
            // 수동으로 디테일한 설정
            if (hasTokenExpired(auth2AuthorizedClient.getAccessToken())
                && null != auth2AuthorizedClient.getRefreshToken()) {
                ClientRegistration clientRegistration = ClientRegistration
                    .withClientRegistration(auth2AuthorizedClient.getClientRegistration())
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();

                OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(
                    clientRegistration,
                    auth2AuthorizedClient.getPrincipalName(),
                    auth2AuthorizedClient.getAccessToken(),
                    auth2AuthorizedClient.getRefreshToken());

                OAuth2AuthorizeRequest oAuth2AuthorizeRequest = OAuth2AuthorizeRequest
                    .withAuthorizedClient(oAuth2AuthorizedClient)
                    .principal(authentication)
                    .attribute(HttpServletRequest.class.getName(), request)
                    .attribute(HttpServletResponse.class.getName(), response)
                    .build();

                oAuth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
            }

            ClientRegistration clientRegistration = auth2AuthorizedClient.getClientRegistration();
            OAuth2AccessToken accessToken = auth2AuthorizedClient.getAccessToken();

            OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration,
                accessToken);
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            // 사용자 정보 획득
            OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);


            // 인증 처리
            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
            authorityMapper.setPrefix("SYSTEM_");
            Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(
                oAuth2User.getAuthorities());

            OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(
                oAuth2User, grantedAuthorities /*oAuth2User.getAuthorities()*/,
                clientRegistration.getRegistrationId());

            // 인증된 사용자의 상태값 유지
            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);

            model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken);
            model.addAttribute("accessToken",
                auth2AuthorizedClient.getAccessToken().getTokenValue());
            model.addAttribute("refreshToken",
                auth2AuthorizedClient.getRefreshToken().getTokenValue());

            return "home";
        }

        return "redirect:/";
    }

    @GetMapping("/oauth2LoginClientCredentials")
    public String oauth2LoginClientCredentials(Model model, HttpServletRequest request,
        HttpServletResponse response) {
        // Anonymous
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(
                "keycloak").principal(authentication)
            .attribute(HttpServletRequest.class.getName(), request)
            .attribute(HttpServletResponse.class.getName(), response).build();

        OAuth2AuthorizedClient auth2AuthorizedClient = oAuth2AuthorizedClientManager.authorize(
            authorizeRequest);

        // 별도의 인증처리 단계가 필요 없다(user == client)
        // 인가로 절차 종료임

        try {
            model.addAttribute("accessToken",
                auth2AuthorizedClient.getAccessToken().getTokenValue());
        } catch (Exception e) {
            model.addAttribute("authorizedClient", "No data.");
        }

        return "home";
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }

    /*
     * Client Credentials 에서는 인증 과정이 따로 없고 anonymous 객체임
     * */
    @GetMapping("/logout")
    public String logout(Authentication authentication, HttpServletRequest request,
        HttpServletResponse response) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        return "redirect:/";
    }
}
