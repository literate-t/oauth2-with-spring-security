package io.security.oauth2withspringsecurity.filter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

public class CustomOAuth2AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  private static final String DEFAULT_FILTER_PROCESSING_URI = "/oauth2LoginWithPassword/**";

  private final Duration clockSkew = Duration.ofSeconds(3600);

  private final Clock clock = Clock.systemUTC();

  private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

  private final OAuth2AuthorizationSuccessHandler successHandler;

  public CustomOAuth2AuthenticationFilter(
      DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
      OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
    super(DEFAULT_FILTER_PROCESSING_URI);
    this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;

    // 인증이 끝나고 다시 저장해야 한다
    // saveAuthorizedClient(..)에서 principal이 키인데
    // 익명 상태에서도 저장이 되기 때문
    successHandler = (authorizedClient, principal, attributes) -> {
      oAuth2AuthorizedClientRepository
          .saveAuthorizedClient(authorizedClient, principal,
              (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
              (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));

      System.out.println("Authorized Client" + authorizedClient);
      System.out.println("Principal" + principal);
      System.out.println("attributes" + attributes);
    };

    oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

    // AnonymousAuthenticationToken은 UsernamePasswordAuthenticationFilter 이후에나 등장하는데
    // 우리는 지금 이 필터를 UsernamePasswordAuthenticationFilter 이전에 넣었다
    // 그러므로 null이 나올 수밖에 없다네
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if (null == authentication) {
      authentication = new AnonymousAuthenticationToken("anonymous", "anonymousUser",
          AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

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
      if (hasTokenExpired(auth2AuthorizedClient.getAccessToken())
          && null != auth2AuthorizedClient.getRefreshToken()) {
        oAuth2AuthorizedClientManager.authorize(authorizeRequest);
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

//      이거 없어도 될 것 같은데?..
//      SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);

      // oAuth2AuthorizedClientRepository에 인증된 사용자를 새로 저장
      successHandler.onAuthorizationSuccess(auth2AuthorizedClient, oAuth2AuthenticationToken,
          createAttributes(request, response));

      // 호출하는 부모 필터로 리턴해줘야 한다
      return oAuth2AuthenticationToken;
    }

    return null;
  }

  private boolean hasTokenExpired(OAuth2Token token) {
    return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
  }

  private static Map<String, Object> createAttributes(HttpServletRequest servletRequest,
      HttpServletResponse servletResponse) {
    Map<String, Object> attributes = new HashMap<>();
    attributes.put(HttpServletRequest.class.getName(), servletRequest);
    attributes.put(HttpServletResponse.class.getName(), servletResponse);
    return attributes;
  }
}
