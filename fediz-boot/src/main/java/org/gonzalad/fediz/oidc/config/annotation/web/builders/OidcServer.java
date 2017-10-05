package org.gonzalad.fediz.oidc.config.annotation.web.builders;

import java.util.Arrays;

import org.apache.cxf.Bus;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.services.AccessTokenService;
import org.apache.cxf.rs.security.oauth2.services.AuthorizationService;
import org.apache.cxf.rs.security.oauth2.services.TokenIntrospectionService;
import org.apache.cxf.rs.security.oidc.idp.OidcConfigurationService;
import org.apache.cxf.rs.security.oidc.idp.OidcKeysService;
import org.apache.cxf.rs.security.oidc.idp.UserInfoService;

/**
 * @author agonzalez
 */
public class OidcServer {
    private OAuthDataProvider authDataProvider;
    private AccessTokenService tokenEndpoint;
    private TokenIntrospectionService introspectionEndpoint;
    private AuthorizationService authorizationEndpoint;
    private OidcConfigurationService discoveryEndpoint;
    private OidcKeysService jwkEndpoint;
    private UserInfoService userInfoEndpoint;
    private Bus bus;

    public void setBus(Bus bus) {
        this.bus = bus;
    }

    public void setAuthDataProvider(OAuthDataProvider authDataProvider) {
        this.authDataProvider = authDataProvider;
    }

    public void setTokenEndpoint(AccessTokenService tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public void setIntrospectionEndpoint(TokenIntrospectionService introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
    }

    public void setAuthorizationEndpoint(AuthorizationService authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public void setDiscoveryEndpoint(OidcConfigurationService discoveryEndpoint) {
        this.discoveryEndpoint = discoveryEndpoint;
    }

    public void setJwkEndpoint(OidcKeysService jwkEndpoint) {
        this.jwkEndpoint = jwkEndpoint;
    }

    public void setUserInfoEndpoint(UserInfoService userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public void start() {
//        endpoint.setBus(bus);
//        endpoint.setServiceBeans(Arrays.<Object>asList(configurationService));
//        endpoint.setAddress("/.well-known");
//        endpoint.init();
//        return endpoint;
    }

    public void stop() {

    }
}
