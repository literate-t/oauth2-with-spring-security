package io.security.oauth2withspringsecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

  private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

  public HomeController(OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
    this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
  }


  @GetMapping("/home")
  public String home(Model model, Authentication authentication) {
    OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientService.loadAuthorizedClient(
        "keycloak", authentication.getName());

    model.addAttribute("accessToken", oAuth2AuthorizedClient.getAccessToken().getTokenValue());
    model.addAttribute("refreshToken", oAuth2AuthorizedClient.getRefreshToken().getTokenValue());
    model.addAttribute("oAuth2AuthenticationToken", authentication);

    return "home";
  }

//  @GetMapping("/home")
//  public String home() {
//    return "homeGrantType2";
//  }
}
