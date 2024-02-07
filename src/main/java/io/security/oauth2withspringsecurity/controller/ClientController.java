package io.security.oauth2withspringsecurity.controller;

import java.util.Arrays;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ClientController {

  private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

  public ClientController(OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
    this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;
  }

  @GetMapping("/client")
  // 인증된 사용자가 아니면 authentication에 null이 들어온다
  public String client(/*Authentication authentication,*/ HttpServletRequest request, Model model) {
    String clientRegistrationId = "keycloak";
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    OAuth2AuthorizedClient authorizedClient1 = oAuth2AuthorizedClientRepository.loadAuthorizedClient(
        clientRegistrationId, authentication,
        request);

//     authorizedClient2 -> null
//    OAuth2AuthorizedClient authorizedClient2 = oAuth2AuthorizedClientService.loadAuthorizedClient(
//        clientRegistrationId,
//        authentication.getName());

    OAuth2AccessToken accessToken = authorizedClient1.getAccessToken();

    DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
    // 인가 서버와 통신함
    OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(
        new OAuth2UserRequest(authorizedClient1.getClientRegistration(), accessToken));

    OAuth2AuthenticationToken auth2AuthenticationToken = new OAuth2AuthenticationToken(oAuth2User,
        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")),
        authorizedClient1.getClientRegistration().getRegistrationId());

    SecurityContextHolder.getContext().setAuthentication(auth2AuthenticationToken);

    model.addAttribute("accessToken", accessToken.getTokenValue());
    model.addAttribute("refreshToken",
        authorizedClient1.getRefreshToken() == null ? "No Refresh token"
            : authorizedClient1.getRefreshToken().getTokenValue());
    model.addAttribute("principalName", oAuth2User.getName());
    model.addAttribute("clientName", authorizedClient1.getClientRegistration().getClientName());

    return "client";
  }
}
