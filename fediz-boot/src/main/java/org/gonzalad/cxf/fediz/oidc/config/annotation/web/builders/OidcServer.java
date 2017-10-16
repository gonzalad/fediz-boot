package org.gonzalad.cxf.fediz.oidc.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.Bus;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.rs.security.oauth2.provider.ClientRegistrationProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author agonzalez
 */
public class OidcServer {
    private OAuthDataProvider authDataProvider;
    private JAXRSServerFactoryBean discoveryEndpoint;
    private JAXRSServerFactoryBean jwkEndpoint;
    private JAXRSServerFactoryBean userInfoEndpoint;
    private Bus bus;
    private JAXRSServerFactoryBean oauth2Endpoint;
    private JAXRSServerFactoryBean idpEndpoint;
    private String basePath;
    private ClientRegistrationProvider clientRegistrationProvider;

    public void setBasePath(String basePath) {
        this.basePath = basePath != null ? basePath : "";
        //        if (!this.basePath.isEmpty() && !this.basePath.endsWith("/")) {
//            this.basePath += "/";
//        }
    }

    public void setBus(Bus bus) {
        this.bus = bus;
    }

    public void setAuthDataProvider(OAuthDataProvider authDataProvider) {
        this.authDataProvider = authDataProvider;
    }

    public void setDiscoveryEndpoint(JAXRSServerFactoryBean discoveryEndpoint) {
        this.discoveryEndpoint = discoveryEndpoint;
    }

    public void setJwkEndpoint(JAXRSServerFactoryBean jwkEndpoint) {
        this.jwkEndpoint = jwkEndpoint;
    }

    public void setUserInfoEndpoint(JAXRSServerFactoryBean userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public void setOAuth2Endpoint(JAXRSServerFactoryBean oauth2Endpoint) {
        this.oauth2Endpoint = oauth2Endpoint;
    }

    public void start() {
        Optional.ofNullable(discoveryEndpoint).ifPresent(it -> it.init());
        Optional.ofNullable(jwkEndpoint).ifPresent(it -> it.init());
        Optional.ofNullable(userInfoEndpoint).ifPresent(it -> it.init());
        Optional.ofNullable(oauth2Endpoint).ifPresent(it -> it.init());
        Optional.ofNullable(idpEndpoint).ifPresent(it -> it.init());
    }

    public void stop() {
    }

    public void setIdpEndpoint(JAXRSServerFactoryBean idpEndpoint) {
        this.idpEndpoint = idpEndpoint;
    }

    public void configure(HttpSecurity http) throws Exception {
        authorize(discoveryEndpoint, http, (it) -> it.permitAll());
        authorize(idpEndpoint, http, (it) -> it.authenticated());
        authorize(jwkEndpoint, http, (it) -> it.permitAll());
        authorize(oauth2Endpoint, http, (it) -> it.permitAll());
        authorize(userInfoEndpoint, http, (it) -> it.permitAll());
        disableCsrfForSpecificEndpoints(http);
    }

    private void disableCsrfForSpecificEndpoints(HttpSecurity http) throws Exception {
        RequestMatcher csrfRequestMatcher = new RequestMatcher() {

            private List<AntPathRequestMatcher> requestMatchers = new ArrayList<>();

            {
                addEndpoint(discoveryEndpoint);
                addEndpoint(jwkEndpoint);
                addEndpoint(oauth2Endpoint);
                addEndpoint(userInfoEndpoint);
            }

            private void addEndpoint(JAXRSServerFactoryBean endpoint) {
                if (endpoint != null && endpoint.getAddress() != null) {
                    requestMatchers.add(new AntPathRequestMatcher(basePath + endpoint.getAddress()));
                }
            }

            @Override
            public boolean matches(HttpServletRequest request) {
                for (AntPathRequestMatcher rm : requestMatchers) {
                    if (rm.matches(request)) {
                        return false;
                    }
                }
                return true;
            }
        };
        http.csrf().disable();//requireCsrfProtectionMatcher(csrfRequestMatcher);
    }

    private void authorize(JAXRSServerFactoryBean endpoint, HttpSecurity http,
                           Consumer<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.AuthorizedUrl> authorizedUrl) throws Exception {
        if (endpoint != null && endpoint.getAddress() != null) {
            authorizedUrl.accept(http.authorizeRequests().antMatchers(basePath + endpoint.getAddress() + "/**"));
        }
    }

    public void setClientRegistrationProvider(ClientRegistrationProvider clientRegistrationProvider) {
        this.clientRegistrationProvider = clientRegistrationProvider;
    }
}
