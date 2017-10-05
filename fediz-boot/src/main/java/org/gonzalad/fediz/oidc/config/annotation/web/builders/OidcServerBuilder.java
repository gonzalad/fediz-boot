package org.gonzalad.fediz.oidc.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.cxf.Bus;
import org.apache.cxf.fediz.service.oidc.FedizSubjectCreator;
import org.apache.cxf.fediz.service.oidc.OAuthDataProviderImpl;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.rs.security.oauth2.grants.refresh.RefreshTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.AccessTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.SubjectCreator;
import org.apache.cxf.rs.security.oauth2.services.AccessTokenService;
import org.apache.cxf.rs.security.oauth2.services.AuthorizationService;
import org.apache.cxf.rs.security.oauth2.services.RedirectionBasedGrantService;
import org.apache.cxf.rs.security.oauth2.services.TokenIntrospectionService;
import org.apache.cxf.rs.security.oidc.idp.IdTokenResponseFilter;
import org.apache.cxf.rs.security.oidc.idp.OidcAuthorizationCodeService;
import org.apache.cxf.rs.security.oidc.idp.OidcConfigurationService;
import org.apache.cxf.rs.security.oidc.idp.OidcHybridService;
import org.apache.cxf.rs.security.oidc.idp.OidcKeysService;
import org.apache.cxf.rs.security.oidc.idp.UserInfoService;
import org.springframework.boot.autoconfigure.web.ServerProperties;

/**
 * @author agonzalez
 */
public class OidcServerBuilder {

    private static final String GRANT_REFRESH = "refresh";

    private static final String GRANT_AUTHORIZATION_CODE = "authorization_code";

    private static final String GRANT_IMPLICIT = "implicit";

    private static final String SCOPE_OPENID = "openid";

    private static final String SCOPE_ROLES = "roles";

    /**
     * List of supported grants.
     * <p>
     * See list in https://tools.ietf.org/html/rfc7591
     */
    private static final List<String> ACCEPTED_GRANTS = Arrays.asList(GRANT_REFRESH, "password", GRANT_AUTHORIZATION_CODE, GRANT_IMPLICIT, "client_credentials");

    private String basePath;

    private String issuer;

    private List<JAXRSServerFactoryBean> endpoints = new ArrayList<>();

    private OAuthDataProvider oauthDataProvider;

    private AccessTokenService accessTokenService;

    private List<String> grants;

    private TokenIntrospectionService tokenIntrospectionService;

    private boolean tokenIntrospectionDisabled;

    private AuthorizationService authorizationService;

    private List<String> scopesRequiringNoConsent;

    private boolean skipAuthorizationWithOidcScope;

    private Map<String, String> supportedClaims;

    public OidcServerBuilder(ServerProperties serverProperties) {
        if (serverProperties == null) {
            throw new IllegalArgumentException("Parameter serverProperties is required");
        }
        this.oauthDataProvider = Defaults.authDataProvider(serverProperties);
        this.grants = Defaults.grants();
        this.scopesRequiringNoConsent = Defaults.scopesRequiringNoConsent();
    }

    public CxfBuilder cxf() {
        // be cautious : handle reentrancy...
        return new CxfBuilder();
    }

    public OidcServerBuilder endpoint(JAXRSServerFactoryBean endpoint) {
        endpoints.add(endpoint);
        return this;
    }

    public OidcServer build() {
        OidcServer oidcServer = new OidcServer();
        oidcServer.setAuthDataProvider(oauthDataProvider);
        oidcServer.setTokenEndpoint(buildTokenEndpoint());
        oidcServer.setIntrospectionEndpoint(buildIntrospectionEndpoint());
        //oidcServer.setTokenRevocationEndpoint(buildRevocationEndpoint());
        //oidcServer.setDiscoveryEndpoint(oauthDataProvider);
        oidcServer.setAuthorizationEndpoint(buildAuthorizationEndpoint());
        oidcServer.setDiscoveryEndpoint(buildDiscoveryEndpoint());
//        oidcServer.setLogoutEndpoint(buildLogoutEndpoint());
        oidcServer.setJwkEndpoint(buildJwkEndpoint());
        oidcServer.setUserInfoEndpoint(buildUserInfoEndpoint());
//        oidcServer.setDynamicClientRegistrationEndpoint(oauthDataProvider);
//        oidcServer.setUserConsole(oauthDataProvider);
//        oidcServer.setAdditionalEndpoints(endpoints);
        return oidcServer;
    }

    private UserInfoService buildUserInfoEndpoint() {
        UserInfoService userInfoService = new UserInfoService();
        userInfoService.setOauthDataProvider(oauthDataProvider);
        userInfoService.setJwsRequired(false);
        return userInfoService;
    }

    private AuthorizationService buildAuthorizationEndpoint() {
        if (authorizationService != null) {
            return authorizationService;
        }
        authorizationService = new AuthorizationService();
        List<RedirectionBasedGrantService> services = new ArrayList<>();
        SubjectCreator subjectCreator = buildSubjectCreator();
        OidcAuthorizationCodeService authorizationCodeService = new OidcAuthorizationCodeService();
        authorizationCodeService.setDataProvider(oauthDataProvider);
        authorizationCodeService.setSkipAuthorizationWithOidcScope(skipAuthorizationWithOidcScope);
        if (grants.contains(GRANT_IMPLICIT)) {
            authorizationCodeService.setCanSupportPublicClients(true);
        } else {
            authorizationCodeService.setCanSupportPublicClients(false);
        }
        authorizationCodeService.setSubjectCreator(subjectCreator);
        if (grants.contains(GRANT_AUTHORIZATION_CODE)) {
            services.add(authorizationCodeService);
        }
        if (grants.contains(GRANT_IMPLICIT)) {
            OidcHybridService service = new OidcHybridService();
            service.setDataProvider(oauthDataProvider);
            service.setSubjectCreator(subjectCreator);
            service.setScopesRequiringNoConsent(scopesRequiringNoConsent);
            service.setResponseFilter(buildIdTokenResponseFilter());
            service.setCodeService(authorizationCodeService);
            services.add(service);
        }
        return authorizationService;
    }

    private OidcKeysService buildJwkEndpoint() {
        OidcKeysService jwkService = new OidcKeysService();
        return jwkService;
    }

    private OidcConfigurationService buildDiscoveryEndpoint() {
        return new OidcConfigurationService();
    }

    private IdTokenResponseFilter buildIdTokenResponseFilter() {
        return new IdTokenResponseFilter();
    }

    private SubjectCreator buildSubjectCreator() {
        FedizSubjectCreator subjectCreator = new FedizSubjectCreator();
        if (issuer == null) {
            throw new IllegalStateException("issuer property is required");
        }
        subjectCreator.setIdTokenIssuer(issuer);
        subjectCreator.setSupportedClaims(supportedClaims);
        return subjectCreator;
    }

    private TokenIntrospectionService buildIntrospectionEndpoint() {
        if (tokenIntrospectionDisabled) {
            return null;
        }
        TokenIntrospectionService introspectionService = new TokenIntrospectionService();
        introspectionService.setDataProvider(oauthDataProvider);
        return introspectionService;
    }

    private AccessTokenService buildTokenEndpoint() {
        if (accessTokenService != null) {
            return accessTokenService;
        }
        AccessTokenService accessTokenService = new AccessTokenService();
        accessTokenService.setDataProvider(oauthDataProvider);
        accessTokenService.setResponseFilter(buildIdTokenResponseFilter());
        List<AccessTokenGrantHandler> grantHandlers = new ArrayList<>();
        if (grants.contains(GRANT_REFRESH)) {
            RefreshTokenGrantHandler refreshTokenGrantHandler = new RefreshTokenGrantHandler();
            refreshTokenGrantHandler.setDataProvider(oauthDataProvider);
            grantHandlers.add(refreshTokenGrantHandler);
        }
        accessTokenService.setGrantHandlers(grantHandlers);
        return accessTokenService;
    }

    public OAuthDataProviderBuilder oauthDataProvider() {
        return new OAuthDataProviderBuilder();
    }

    // Should only be used from our Configuration
    public List<JAXRSServerFactoryBean> getEndpoints() {
        return endpoints;
    }

    // Should only be used from our Configuration
    public OAuthDataProvider getAuthDataProvider() {
        return oauthDataProvider;
    }

    private static class Defaults {

        private static final long DEFAULT_ACCESS_TOKEN_LIFETIME = 1800;

        private static OAuthDataProviderImpl authDataProvider(ServerProperties serverProperties) {
            OAuthDataProviderImpl authDataProvider = new OAuthDataProviderImpl();
            authDataProvider.setSupportedScopes(supportedScopes());
            authDataProvider.setInvisibleToClientScopes(invisibleToClientScopes());
            authDataProvider.setSupportedScopes(supportedScopes());
            long sessionTimeout = serverProperties.getSession().getTimeout() != null ? serverProperties.getSession().getTimeout() : 0;
            long accessTokenLifetime = sessionTimeout > 0 ? sessionTimeout : DEFAULT_ACCESS_TOKEN_LIFETIME;
            authDataProvider.setAccessTokenLifetime(accessTokenLifetime);
            return authDataProvider;
        }

        private static Map<String, String> supportedScopes() {
            Map<String, String> scopes = new HashMap<String, String>();
            scopes.put("openid", "Access the authentication claims");
            scopes.put("email", "Access the email address");
            scopes.put("profile", "Access the profile claims");
            scopes.put("roles", "Access the user roles");
            scopes.put("refreshToken", "Refresh access tokens");
            return scopes;
        }

        private static List<String> defaultScopes() {
            return Arrays.asList("openid");
        }

        private static List<String> invisibleToClientScopes() {
            return Arrays.asList("refreshToken");
        }

        public static List<String> grants() {
            return Arrays.asList(GRANT_REFRESH, GRANT_AUTHORIZATION_CODE);
        }

        public static List<String> scopesRequiringNoConsent() {
            return Arrays.asList(SCOPE_OPENID, SCOPE_ROLES);
        }
    }

    public class OAuthDataProviderBuilder {

        public OAuthDataProviderBuilder custom(
                OAuthDataProvider oauthDataProvider) {
            OidcServerBuilder.this.oauthDataProvider = oauthDataProvider;
            return this;
        }

        public OAuthDataProviderBuilder supportedScopes(String... supportedScopes) {
            List<String> scopes = new ArrayList<String>(Arrays.asList(supportedScopes));
            // todo handle scope label (i18n: use spring MessageSource)
            castToImpl("supportedScopes").setSupportedScopes(scopes.stream().collect(Collectors.toMap(it -> it, it -> it)));
            return this;
        }

        //... add the other builder methods in a similar way

        private OAuthDataProviderImpl castToImpl(String callingMethodName) {
            if (!(OidcServerBuilder.this.oauthDataProvider instanceof OAuthDataProviderImpl)) {
                throw new IllegalStateException(String.format("Calling %s on a custom OAuthDataProvider is fobidden", callingMethodName));
            }
            return (OAuthDataProviderImpl) OidcServerBuilder.this.oauthDataProvider;
        }

        public OidcServerBuilder and() {
            return OidcServerBuilder.this;
        }
    }

    public class AuthorizationCodeBuilder {

        public AuthorizationCodeBuilder scopesRequiringNoConsent(String... scopesRequiringNoConsent) {
            OidcServerBuilder.this.scopesRequiringNoConsent = new ArrayList<String>(Arrays.asList(scopesRequiringNoConsent));
            return this;
        }

        public AuthorizationCodeBuilder skipAuthorizationWithOidcScope(boolean skip) {
            OidcServerBuilder.this.skipAuthorizationWithOidcScope = skip;
            return this;
        }

        public AuthorizationCodeBuilder issuer(String issuer) {
            OidcServerBuilder.this.issuer = issuer;
            return this;
        }

        public AuthorizationCodeBuilder supportedClaims(Map<String, String> supportedClaims) {
            OidcServerBuilder.this.supportedClaims = supportedClaims;
            return this;
        }
    }

    public class TokenIntrospectionBuilder {

        public TokenIntrospectionBuilder custom(
                TokenIntrospectionService tokenIntrospectionService) {
            OidcServerBuilder.this.tokenIntrospectionService = tokenIntrospectionService;
            return this;
        }

        public TokenIntrospectionBuilder disable() {
            OidcServerBuilder.this.tokenIntrospectionDisabled = true;
            return this;
        }

        public OidcServerBuilder and() {
            return OidcServerBuilder.this;
        }
    }

    public class TokenServiceBuilder {

        public TokenServiceBuilder custom(
                AccessTokenService accessTokenService) {
            OidcServerBuilder.this.accessTokenService = accessTokenService;
            return this;
        }

        public TokenServiceBuilder grantHandlers(String... grantHandlers) {
            List<String> grants = new ArrayList<String>(Arrays.asList(grantHandlers));
            List<String> invalidGrants = grants.stream().filter(it -> !ACCEPTED_GRANTS.contains(it)).collect(Collectors.toList());
            if (invalidGrants.size() > 0) {
                throw new IllegalArgumentException(String.format("The following grants are not supported by fediz %s", invalidGrants));
            }
            OidcServerBuilder.this.grants = grants;
            return this;
        }

        //... add the other builder methods in a similar way

        private OAuthDataProviderImpl castToImpl(String callingMethodName) {
            if (!(OidcServerBuilder.this.oauthDataProvider instanceof OAuthDataProviderImpl)) {
                throw new IllegalStateException(String.format("Calling %s on a custom OAuthDataProvider is fobidden", callingMethodName));
            }
            return (OAuthDataProviderImpl) OidcServerBuilder.this.oauthDataProvider;
        }

        public OidcServerBuilder and() {
            return OidcServerBuilder.this;
        }
    }

    public class CxfBuilder {

        private Bus bus;

        public CxfBuilder bus(Bus bus) {
            this.bus = bus;
            return this;
        }

        public OidcServerBuilder and() {
            return OidcServerBuilder.this;
        }
    }
}
