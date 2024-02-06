package io.security.oauth2withspringsecurity;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class CustomOAuth2AuthorizationRequestResolver implements
    OAuth2AuthorizationRequestResolver {

  private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
  private static final Consumer<Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
      .withPkce();

  private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;
  private final AntPathRequestMatcher authorizationRequestMatcher;

  public CustomOAuth2AuthorizationRequestResolver(ClientRegistrationRepository repository,
      String baseUri) {
    this.authorizationRequestMatcher = new AntPathRequestMatcher(
        baseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(repository, baseUri);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    String registrationId = resolveRegistrationId(request);
    if (null == registrationId) {
      return null;
    }

    if (registrationId.equals("keycloakWithPKCE")) {
      OAuth2AuthorizationRequest defaultRequest = defaultResolver.resolve(request);
      return customResolve(defaultRequest);
    }

    return defaultResolver.resolve(request);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request,
      String clientRegistrationId) {

    if (null == clientRegistrationId) {
      return null;
    }

    if (clientRegistrationId.equals("keycloakWithPKCE")) {
      OAuth2AuthorizationRequest defaultRequest = defaultResolver.resolve(request);
      return customResolve(defaultRequest);
    }

    return defaultResolver.resolve(request);
  }

  private OAuth2AuthorizationRequest customResolve(OAuth2AuthorizationRequest defaultRequest) {
    Map<String, Object> extraParam = new HashMap<>();
    extraParam.put("customName1", "customValue1");
    extraParam.put("customName2", "customValue2");

    Builder builder = OAuth2AuthorizationRequest.from(defaultRequest)
        .additionalParameters(extraParam);
    DEFAULT_PKCE_APPLIER.accept(builder);

    return builder.build();
  }


  private String resolveRegistrationId(HttpServletRequest request) {
    if (this.authorizationRequestMatcher.matches(request)) {
      return this.authorizationRequestMatcher.matcher(request).getVariables()
          .get(REGISTRATION_ID_URI_VARIABLE_NAME);
    }
    return null;
  }
}
