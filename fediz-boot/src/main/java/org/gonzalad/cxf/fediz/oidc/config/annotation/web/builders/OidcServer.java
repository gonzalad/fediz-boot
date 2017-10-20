package org.gonzalad.cxf.fediz.oidc.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.Bus;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author agonzalez
 */
public class OidcServer {

    private static final String USER_CONSOLE_ENDPOINT = "user.console";
    private static final String IDP_ENDPOINT = "idp.console";
    private static final String DISCOVERY_ENDPOINT = "discovery";
    private static final String JWK_ENDPOINT = "jwk";
    private static final String USER_INFO_ENDPOINT = "user.info";
    private static final String OAUTH2_ENDPOINT = "oauth2";
    private static final String REGISTRATIOB_ENDPOINT = "registration";
    private static final List<String> UI_ENDPOINTS = Arrays.asList(IDP_ENDPOINT, USER_CONSOLE_ENDPOINT);
    private Map<String, JAXRSServerFactoryBean> endpoints = new HashMap<>();
    private Bus bus;
    private String basePath;

    public void start() {
        endpoints.values().stream().forEach(it -> it.init());
    }

    public void configure(HttpSecurity http) throws Exception {
        List<JAXRSServerFactoryBean> permitAllEndpoints = endpoints.entrySet().stream()
                .filter(it -> !UI_ENDPOINTS.contains(it.getKey()))
                .map(it -> it.getValue())
                .collect(Collectors.toList());
        for (JAXRSServerFactoryBean endpoint : permitAllEndpoints) {
            authorize(endpoint, http, (it) -> it.permitAll());
        }
        http.authorizeRequests().antMatchers("/static/**").permitAll();
        disableCsrfForSpecificEndpoints(http);
    }

    private void disableCsrfForSpecificEndpoints(HttpSecurity http) throws Exception {
        RequestMatcher csrfRequestMatcher = new RequestMatcher() {

            private final HashSet<String> allowedMethods = new HashSet<String>(
                    Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS"));

            private List<AntPathRequestMatcher> requestMatchers = new ArrayList<>();

            {
                List<String> csrfEnabledEndpoints = Arrays.asList(IDP_ENDPOINT, USER_CONSOLE_ENDPOINT);
                endpoints.entrySet().stream()
                        .filter(it -> !UI_ENDPOINTS.contains(it.getKey()))
                        .forEach(it -> addEndpoint(it.getValue()));
            }

            private void addEndpoint(JAXRSServerFactoryBean endpoint) {
                if (endpoint != null && endpoint.getAddress() != null) {
                    requestMatchers.add(new AntPathRequestMatcher(basePath + endpoint.getAddress() + "/**"));
                }
            }

            @Override
            public boolean matches(HttpServletRequest request) {
                for (AntPathRequestMatcher rm : requestMatchers) {
                    if (rm.matches(request)) {
                        return false;
                    }
                }
                if (allowedMethods.contains(request.getMethod())) {
                    return false;
                }
               return true;
            }
        };
        http.csrf().requireCsrfProtectionMatcher(csrfRequestMatcher);
    }

    private void authorize(JAXRSServerFactoryBean endpoint, HttpSecurity http,
                           Consumer<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.AuthorizedUrl> authorizedUrl) throws Exception {
        if (endpoint != null && endpoint.getAddress() != null) {
            authorizedUrl.accept(http.authorizeRequests().antMatchers(basePath + endpoint.getAddress() + "/**"));
        }
    }

    public void setBus(Bus bus) {
        this.bus = bus;
    }

    public void setBasePath(String basePath) {
        this.basePath = basePath != null ? basePath : "";
        //        if (!this.basePath.isEmpty() && !this.basePath.endsWith("/")) {
//            this.basePath += "/";
//        }
    }

    public void setIdpEndpoint(JAXRSServerFactoryBean idpEndpoint) {
        endpoints.put(IDP_ENDPOINT, idpEndpoint);
    }

    public void setUserConsoleEndpoint(JAXRSServerFactoryBean userConsoleEndpoint) {
        endpoints.put(USER_CONSOLE_ENDPOINT, userConsoleEndpoint);
    }

    public void setDynamicClientRegistrationEndpoint(JAXRSServerFactoryBean dynamicClientRegistrationEndpoint) {
        endpoints.put(REGISTRATIOB_ENDPOINT, dynamicClientRegistrationEndpoint);
    }

    public void setDiscoveryEndpoint(JAXRSServerFactoryBean discoveryEndpoint) {
        endpoints.put(DISCOVERY_ENDPOINT, discoveryEndpoint);
    }

    public void setJwkEndpoint(JAXRSServerFactoryBean jwkEndpoint) {
        endpoints.put(JWK_ENDPOINT, jwkEndpoint);
    }

    public void setUserInfoEndpoint(JAXRSServerFactoryBean userInfoEndpoint) {
        endpoints.put(USER_INFO_ENDPOINT, userInfoEndpoint);
    }

    public void setOAuth2Endpoint(JAXRSServerFactoryBean oauth2Endpoint) {
        endpoints.put(OAUTH2_ENDPOINT, oauth2Endpoint);
    }
}
