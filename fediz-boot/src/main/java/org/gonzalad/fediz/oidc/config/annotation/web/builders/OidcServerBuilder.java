package org.gonzalad.fediz.oidc.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.cxf.Bus;
import org.apache.cxf.fediz.service.oidc.FedizSubjectCreator;
import org.apache.cxf.fediz.service.oidc.OAuthDataProviderImpl;
import org.apache.cxf.fediz.service.oidc.PrivateKeyPasswordProviderImpl;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.jaxrs.provider.json.JsonMapObjectProvider;
import org.apache.cxf.rs.security.cors.CrossOriginResourceSharingFilter;
import org.apache.cxf.rs.security.jose.common.PrivateKeyPasswordProvider;
import org.apache.cxf.rs.security.jose.jaxrs.JsonWebKeysProvider;
import org.apache.cxf.rs.security.oauth2.grants.refresh.RefreshTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.AccessTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
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
import org.gonzalad.fediz.oidc.config.annotation.web.configuration.FedizOidcServerProperties;
import org.springframework.boot.context.embedded.Ssl;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_PSWD;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_STORE_ALIAS;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_STORE_FILE;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_STORE_PSWD;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_STORE_TYPE;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_SIGNATURE_INCLUDE_KEY_ID;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_SIGNATURE_KEY_PSWD_PROVIDER;

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

    private OAuth2EndpointBuilder oAuth2EndpointBuilder = new OAuth2EndpointBuilder();

    private JwkEndpointBuilder jwkEndpointBuilder = new JwkEndpointBuilder();

    private IdpEndpointBuilder idpEndpointBuilder = new IdpEndpointBuilder();

    private DiscoveryEndpointBuilder discoveryEndpointBuilder = new DiscoveryEndpointBuilder();

    private CxfBuilder cxfBuilder = new CxfBuilder();

    private FedizOidcServerProperties serverProperties;

    public OidcServerBuilder(FedizOidcServerProperties serverProperties, Bus bus) {
        if (serverProperties == null) {
            throw new IllegalArgumentException("Parameter serverProperties is required");
        }
        this.oauthDataProvider = Defaults.authDataProvider(serverProperties);
        this.grants = Defaults.grants();
        this.scopesRequiringNoConsent = Defaults.scopesRequiringNoConsent();
        this.cxfBuilder.bus = bus;
        this.serverProperties = serverProperties;
    }

    public CxfBuilder cxf() {
        // be cautious : handle reentrancy...
        return cxfBuilder;
    }

    public OAuth2EndpointBuilder oauth2() {
        // be cautious : handle reentrancy...
        return oAuth2EndpointBuilder;
    }

    public IdpEndpointBuilder idp() {
        // be cautious : handle reentrancy...
        return idpEndpointBuilder;
    }

    public JwkEndpointBuilder jwk() {
        // be cautious : handle reentrancy...
        return this.jwkEndpointBuilder;
    }

    public DiscoveryEndpointBuilder discovery() {
        return discoveryEndpointBuilder;
    }

    private PrivateKeyPasswordProvider buildPrivateKeyPasswordProvider() {
        return new PrivateKeyPasswordProviderImpl();
    }

    public OidcServerBuilder endpoint(JAXRSServerFactoryBean endpoint) {
        endpoints.add(endpoint);
        return this;
    }

    public OidcServer build() {
        OidcServer oidcServer = new OidcServer();
        oidcServer.setBus(cxfBuilder.bus);
        oidcServer.setAuthDataProvider(oauthDataProvider);
        oidcServer.setOAuth2Endpoint(buildOAuth2Endpoint());
        oidcServer.setDiscoveryEndpoint(buildDiscoveryEndpoint());
//        oidcServer.setLogoutEndpoint(buildLogoutEndpoint());
        oidcServer.setJwkEndpoint(buildJwkEndpoint());
        oidcServer.setUserInfoEndpoint(buildUserInfoEndpoint());
        oidcServer.setIdpEndpoint(buildIdpEndpoint());
//        oidcServer.setDynamicClientRegistrationEndpoint(oauthDataProvider);
//        oidcServer.setUserConsole(oauthDataProvider);
//        oidcServer.setAdditionalEndpoints(endpoints);
        return oidcServer;
    }

    private JAXRSServerFactoryBean buildIdpEndpoint() {
        buildKeyManagementProperties(idpEndpointBuilder);
        // TODO handle viewProvider endpoint and bundle default resources inside jar (i.e use Spring Boot here ?)
        List<Object> defaultProviders = Arrays.asList(buildOAuthJsonProvider());
        List<Object> services = new ArrayList<>();
        Optional.ofNullable(buildAuthorizationService()).ifPresent(it -> services.add(it));
        // TODO logout
        return buildEndpoint(idpEndpointBuilder, services, Collections.emptyMap(), defaultProviders);
    }

    private JAXRSServerFactoryBean buildOAuth2Endpoint() {
        buildKeyManagementProperties(oAuth2EndpointBuilder);
        List<Object> defaultProviders = Arrays.asList(buildOAuthJsonProvider());
        List<Object> services = new ArrayList<>();
        Optional.ofNullable(buildTokenService()).ifPresent(it -> services.add(it));
        Optional.ofNullable(buildIntrospectionEndpoint()).ifPresent(it -> services.add(it));
        return buildEndpoint(oAuth2EndpointBuilder, services, Collections.emptyMap(), defaultProviders);
    }

    private JAXRSServerFactoryBean buildDiscoveryEndpoint() {
        buildKeyManagementProperties(oAuth2EndpointBuilder);
        return buildEndpoint(discoveryEndpointBuilder, buildDiscoveryService());
    }

    private JAXRSServerFactoryBean buildUserInfoEndpoint() {
        EndpointBuilder endpointBuilder = new EndpointBuilder<>();
        endpointBuilder.address("/users");
        buildKeyManagementProperties(endpointBuilder);
        List<Object> defaultProviders = Arrays.asList(corsFilter(), new JsonMapObjectProvider());
        UserInfoService userInfoService = new UserInfoService();
        userInfoService.setOauthDataProvider(oauthDataProvider);
        userInfoService.setJwsRequired(false);
        return buildEndpoint(endpointBuilder, userInfoService, Collections.emptyMap(), defaultProviders);
    }

    private Object buildOAuthJsonProvider() {
        return new OAuthJSONProvider();
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

    private UserInfoService buildUserInfoService() {
        UserInfoService userInfoService = new UserInfoService();
        userInfoService.setOauthDataProvider(oauthDataProvider);
        userInfoService.setJwsRequired(false);
        return userInfoService;
    }

    private AuthorizationService buildAuthorizationService() {
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

    private JAXRSServerFactoryBean buildJwkEndpoint() {
        buildKeyManagementProperties(jwkEndpointBuilder);
        List<Object> defaultProviders = Arrays.asList(corsFilter(), new JsonWebKeysProvider());
        return buildEndpoint(jwkEndpointBuilder, new OidcKeysService(), Collections.emptyMap(), defaultProviders);
    }

    private void buildKeyManagementProperties(EndpointBuilder endpointBuilder) {
        endpointBuilder.properties = buildKeyManagementProperties(endpointBuilder.properties);
    }

    /**
     * Hack code to transform Spring Ssl information to information usable
     * by JwsUtils and KeyManagementUtils.
     * <p>
     * if existingProperties already contain a rs.security.signature, we don't do nothing
     * (in this case, we suppose the developer wanted to customize himself the properties).
     * <p>
     * Notes: we don't specify the algorithm (RSSEC_SIGNATURE_ALGORITHM), so it will default
     * to RS256.
     *
     * @param existingProperties existing endpoint properties
     * @return the new endpoint properties with the added rs.security.signature.* keys
     */
    private Map<String, Object> buildKeyManagementProperties(Map<String, Object> existingProperties) {
        if (existingProperties != null && existingProperties.keySet().stream().filter(it -> it.startsWith("rs.security.signature")).findAny().isPresent()) {
            return existingProperties;
        }
        Map<String, Object> newMap = new HashMap<>(existingProperties != null ? existingProperties : Collections.emptyMap());
        Ssl ssl = serverProperties.getJwk().getLocalStore();
        // TODO: we must handle relative keyStoreFile locations.
        // I made a single test with absolute file, which is ugly :
        // fediz.oidc.ssl.key-store: /home/agonzalez/git-projects/fediz-boot/fediz-boot/src/main/resources/samples/oidc.jks
        //
        // and we should also check if Spring SSL handles classpath: or any other springies goodies and be able
        // to have the same behaviour (in this case using here a resourceLoader is need be).
        //
        // and finally, Fediz appears to be able to use a keyClient (what is it ? appears interesting... could we support
        // that easily ?)
        Optional.ofNullable(ssl.getKeyStore()).ifPresent(it -> newMap.put(RSSEC_KEY_STORE_FILE, ssl.getKeyStore()));
        Optional.ofNullable(ssl.getKeyStoreType()).ifPresent(it -> newMap.put(RSSEC_KEY_STORE_TYPE, ssl.getKeyStoreType()));
        Optional.ofNullable(ssl.getKeyStorePassword()).ifPresent(it -> newMap.put(RSSEC_KEY_STORE_PSWD, ssl.getKeyStorePassword()));
        Optional.ofNullable(ssl.getKeyAlias()).ifPresent(it -> newMap.put(RSSEC_KEY_STORE_ALIAS, ssl.getKeyAlias()));
        Optional.ofNullable(ssl.getKeyPassword()).ifPresent(it -> newMap.put(RSSEC_KEY_PSWD, ssl.getKeyPassword()));
        newMap.put(RSSEC_SIGNATURE_INCLUDE_KEY_ID, "true");
        newMap.put(RSSEC_SIGNATURE_KEY_PSWD_PROVIDER, buildPrivateKeyPasswordProvider());
        return newMap;
    }

    private CrossOriginResourceSharingFilter corsFilter() {
        CrossOriginResourceSharingFilter corsFilter = new CrossOriginResourceSharingFilter();
        corsFilter.setAllowHeaders(Arrays.asList("Authorization"));
        return corsFilter;
    }

    private JAXRSServerFactoryBean buildEndpoint(EndpointBuilder endpointBuilder, Object service) {
        return buildEndpoint(endpointBuilder, Arrays.asList(service), Collections.emptyMap(), Collections.emptyList());
    }

    private JAXRSServerFactoryBean buildEndpoint(EndpointBuilder endpointBuilder, Object service,
                                                 Map<String, Object> defaultProperties,
                                                 List<Object> defaultProviders) {
        return buildEndpoint(endpointBuilder, Arrays.asList(service), defaultProperties, defaultProviders);
    }

    private JAXRSServerFactoryBean buildEndpoint(EndpointBuilder endpointBuilder, List<Object> services,
                                                 Map<String, Object> defaultProperties,
                                                 List<Object> defaultProviders) {
        if (services == null || services.size() == 0) {
            return null;
        }
        Map<String, Object> properties = endpointBuilder.properties != null ? endpointBuilder.properties : defaultProperties;
        List<Object> providers = endpointBuilder.providers != null ? endpointBuilder.providers : defaultProviders;
        JAXRSServerFactoryBean endpoint = new JAXRSServerFactoryBean();
        endpoint.setAddress(endpointBuilder.address);
        endpoint.setServiceBeans(services);
        endpoint.setBus(cxfBuilder.bus);
        endpoint.setProperties(properties);
        endpoint.setProviders(providers);
        return endpoint;
    }

    private OidcKeysService buildJwkService() {
        OidcKeysService jwkService = new OidcKeysService();
        return jwkService;
    }

    private OidcConfigurationService buildDiscoveryService() {
        return new OidcConfigurationService();
    }

    private IdTokenResponseFilter buildIdTokenResponseFilter() {
        return new IdTokenResponseFilter();
    }

    private SubjectCreator buildSubjectCreator() {
        FedizSubjectCreator subjectCreator = new FedizSubjectCreator();
        subjectCreator.setIdTokenIssuer(serverProperties.getIssuer());
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

    private AccessTokenService buildTokenService() {
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

    private static class Defaults {


        private static OAuthDataProviderImpl authDataProvider(FedizOidcServerProperties serverProperties) {
            OAuthDataProviderImpl authDataProvider = new OAuthDataProviderImpl();
            authDataProvider.setSupportedScopes(supportedScopes());
            authDataProvider.setInvisibleToClientScopes(invisibleToClientScopes());
            authDataProvider.setSupportedScopes(supportedScopes());
            authDataProvider.setAccessTokenLifetime(serverProperties.getAccessTokenLifetime());
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

    public static class EndpointBuilder<B, O extends EndpointBuilder<B, O>> {
        String address;
        List<? extends Object> providers;
        Map<String, Object> properties;

        public O address(String address) {
            this.address = address;
            return getSelf();
        }

        public O properties(Map<String, Object> properties) {
            this.properties = properties;
            return getSelf();
        }

        public O providers(List<? extends Object> providers) {
            this.providers = providers;
            return getSelf();
        }

        private O getSelf() {
            return (O) this;
        }
    }

    public class JwkEndpointBuilder extends EndpointBuilder<OidcServerBuilder, JwkEndpointBuilder> {

        public JwkEndpointBuilder() {
            super.address = "/jwk";
        }
    }

    public class DiscoveryEndpointBuilder extends EndpointBuilder<OidcServerBuilder, JwkEndpointBuilder> {

        public DiscoveryEndpointBuilder() {
            super.address = "/.well-known";
        }
    }

    public class OAuth2EndpointBuilder extends EndpointBuilder<OidcServerBuilder, OAuth2EndpointBuilder> {

        public OAuth2EndpointBuilder() {
            super.address = "/oauth2";
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

            public OAuth2EndpointBuilder and() {
                return OAuth2EndpointBuilder.this;
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

            public OAuth2EndpointBuilder and() {
                return OAuth2EndpointBuilder.this;
            }
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

    public class IdpEndpointBuilder extends EndpointBuilder<OidcServerBuilder, OAuth2EndpointBuilder> {

        public IdpEndpointBuilder() {
            super.address = "/idp";
        }

        public IdpEndpointBuilder and() {
            return IdpEndpointBuilder.this;
        }

        public AuthorizationCodeBuilder authorizationCode() {
            return new AuthorizationCodeBuilder();
        }

        // TODO add logoutBuilder...

        public class AuthorizationCodeBuilder {

            public AuthorizationCodeBuilder scopesRequiringNoConsent(String... scopesRequiringNoConsent) {
                OidcServerBuilder.this.scopesRequiringNoConsent = new ArrayList<String>(Arrays.asList(scopesRequiringNoConsent));
                return this;
            }

            public AuthorizationCodeBuilder skipAuthorizationWithOidcScope(boolean skip) {
                OidcServerBuilder.this.skipAuthorizationWithOidcScope = skip;
                return this;
            }

            public AuthorizationCodeBuilder supportedClaims(Map<String, String> supportedClaims) {
                OidcServerBuilder.this.supportedClaims = supportedClaims;
                return this;
            }

            public IdpEndpointBuilder and() {
                return IdpEndpointBuilder.this;
            }
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
