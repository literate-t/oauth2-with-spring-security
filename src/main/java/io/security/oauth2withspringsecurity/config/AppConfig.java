package io.security.oauth2withspringsecurity.config;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;

@Configuration
public class AppConfig {

  @Bean
  public DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientRepository authorizedClientRepository
  ) {
    OAuth2AuthorizedClientProvider auth2AuthorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .password()
            .clientCredentials()
            .refreshToken()
            .build();

    DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager
        = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository,
        authorizedClientRepository);

    // 원래는 자동으로 successHandler가 등록이 되고 실행도 된다
    OAuth2AuthorizationSuccessHandler authorizationSuccessHandler = (authorizedClient, principal, attributes) -> {
      authorizedClientRepository
          .saveAuthorizedClient(authorizedClient, principal,
              (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
              (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));

      System.out.println("Authorized Client" + authorizedClient);
      System.out.println("Principal" + principal);
      System.out.println("attributes" + attributes);
    };

    oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(authorizationSuccessHandler);

    oAuth2AuthorizedClientManager.setAuthorizedClientProvider(auth2AuthorizedClientProvider);
    oAuth2AuthorizedClientManager.setContextAttributesMapper(contextAttributesMapper());

    return oAuth2AuthorizedClientManager;
  }

  // public interface Function<T, R> {
  //    R apply(T t);
  // }
  // 람다식으로 정의된 함수가 apply로 실행됨
  /*
   * DefaultOAuth2AuthorizedClientManager authorize()에서
   * 		OAuth2AuthorizationContext authorizationContext = contextBuilder.principal(principal)
				.attributes((attributes) -> {
					Map<String, Object> contextAttributes = this.contextAttributesMapper.apply(authorizeRequest);
					if (!CollectionUtils.isEmpty(contextAttributes)) {
						attributes.putAll(contextAttributes);
					}
				})
				.build();
   *  에서 apply로 호출되는 부분임
   * */
  private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {
    return oAuth2AuthorizeRequest -> {
      HttpServletRequest request = oAuth2AuthorizeRequest.getAttribute(
          HttpServletRequest.class.getName());
      Map<String, Object> contextAttributes = new HashMap<>();

      String username = request.getParameter(OAuth2ParameterNames.USERNAME);
      String password = request.getParameter(OAuth2ParameterNames.PASSWORD);

      if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
        contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
        contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
      }

      return contextAttributes;
    };
  }
}
