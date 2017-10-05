package org.gonzalad.fediz.sample.oidc;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.cxf.Bus;
import org.apache.cxf.fediz.service.oidc.OAuthDataProviderImpl;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.rs.security.oauth2.grants.refresh.RefreshTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.AccessTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.services.AccessTokenService;
import org.apache.cxf.rs.security.oidc.idp.IdTokenResponseFilter;
import org.apache.cxf.rs.security.oidc.idp.OidcConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * @author agonzalez
 */
@SpringBootApplication
public class AuthorizationServerApplication {

    @Autowired
    private Bus bus;

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

    /**
     * TODO: http://localhost:8080/services/.well-known/openid-configuration
     * should be available at root and not under /services (but I do't want CXFServlet mapped
     * to root, otherwise it will mask Spring dispatcherServlet)
     *
     * @param configurationService
     * @return
     */
    @Bean
    public JAXRSServerFactoryBean oidcConfigurationServiceEndpoint(
            OidcConfigurationService configurationService) {
        JAXRSServerFactoryBean endpoint = new JAXRSServerFactoryBean();
        endpoint.setBus(bus);
        endpoint.setServiceBeans(Arrays.<Object>asList(configurationService));
        endpoint.setAddress("/.well-known");
        endpoint.init();
        return endpoint;
    }

    @Bean
    public OidcConfigurationService oidcConfigurationService() {
        return new OidcConfigurationService();
    }

    @Bean
    public JAXRSServerFactoryBean tokenServiceServerEndpoint(AccessTokenService accessTokenService) {
        JAXRSServerFactoryBean endpoint = new JAXRSServerFactoryBean();
        endpoint.setBus(bus);
        endpoint.setServiceBeans(Arrays.<Object>asList(accessTokenService));
        endpoint.setAddress("/oauth2");
        endpoint.init();
        return endpoint;
    }

    @Bean
    public AccessTokenService accessTokenService(OAuthDataProvider dataProvider,
                                                 IdTokenResponseFilter idTokenResponseFilter,
                                                 List<AccessTokenGrantHandler> grantHandlers) {
        AccessTokenService accessTokenService = new AccessTokenService();
        accessTokenService.setDataProvider(dataProvider);
        accessTokenService.setResponseFilter(idTokenResponseFilter);
        accessTokenService.setGrantHandlers(grantHandlers);
        accessTokenService.setCanSupportPublicClients(true);
        return accessTokenService;
    }

    @Bean
    public IdTokenResponseFilter idTokenResponseFilter() {
        return new IdTokenResponseFilter();
    }

    @Bean
    public RefreshTokenGrantHandler refreshTokenGrantHandler(OAuthDataProvider dataProvider) {
        RefreshTokenGrantHandler refreshTokenGrantHandler = new RefreshTokenGrantHandler();
        refreshTokenGrantHandler.setDataProvider(dataProvider);
        return refreshTokenGrantHandler;
    }

    @Bean(initMethod = "init", destroyMethod = "close")
    public OAuthDataProvider oauthDataProvider() {
        OAuthDataProviderImpl oauthDataProvider = new OAuthDataProviderImpl();
        oauthDataProvider.setSupportedScopes(supportedScopes());
        oauthDataProvider.setDefaultScopes(defaultScopes());
        oauthDataProvider.setInvisibleToClientScopes(invisibleToClientScopes());
        return oauthDataProvider;
    }

    private List<String> defaultScopes() {
        return Arrays.asList("openid");
    }

    private List<String> invisibleToClientScopes() {
        return Arrays.asList("refreshToken");
    }

    private Map<String, String> supportedScopes() {
        Map<String, String> scopes = new HashMap<String, String>();
        scopes.put("openid", "Access the authentication claims");
        scopes.put("email", "Access the email address");
        scopes.put("profile", "Access the profile claims");
        scopes.put("roles", "Access the user roles");
        scopes.put("refreshToken", "Refresh access tokens");
        return scopes;
    }
}
