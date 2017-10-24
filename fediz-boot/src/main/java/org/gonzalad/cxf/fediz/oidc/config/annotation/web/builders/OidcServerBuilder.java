package org.gonzalad.cxf.fediz.oidc.config.annotation.web.builders;

import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_PSWD;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_STORE_ALIAS;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_STORE_FILE;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_STORE_PSWD;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_KEY_STORE_TYPE;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_SIGNATURE_INCLUDE_KEY_ID;
import static org.apache.cxf.rs.security.jose.common.JoseConstants.RSSEC_SIGNATURE_KEY_PSWD_PROVIDER;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.cxf.Bus;
import org.apache.cxf.fediz.service.oidc.ClaimsMapper;
import org.apache.cxf.fediz.service.oidc.FedizSubjectCreator;
import org.apache.cxf.fediz.service.oidc.OAuthDataProviderImpl;
import org.apache.cxf.fediz.service.oidc.PrivateKeyPasswordProviderImpl;
import org.apache.cxf.fediz.service.oidc.clients.ClientRegistrationService;
import org.apache.cxf.fediz.service.oidc.console.UserConsoleService;
import org.apache.cxf.fediz.service.oidc.logout.BackChannelLogoutHandler;
import org.apache.cxf.fediz.service.oidc.logout.LogoutHandler;
import org.apache.cxf.fediz.service.oidc.logout.LogoutService;
import org.apache.cxf.fediz.service.oidc.logout.TokenCleanupHandler;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.jaxrs.provider.json.JsonMapObjectProvider;
import org.apache.cxf.jaxrs.utils.ResourceUtils;
import org.apache.cxf.rs.security.cors.CrossOriginResourceSharingFilter;
import org.apache.cxf.rs.security.jose.common.PrivateKeyPasswordProvider;
import org.apache.cxf.rs.security.jose.jaxrs.JsonWebKeysProvider;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.grants.refresh.RefreshTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.AccessTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.ClientIdProvider;
import org.apache.cxf.rs.security.oauth2.provider.ClientRegistrationProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJSONProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthJoseJwtProducer;
import org.apache.cxf.rs.security.oauth2.provider.ProviderAuthenticationStrategy;
import org.apache.cxf.rs.security.oauth2.provider.SubjectCreator;
import org.apache.cxf.rs.security.oauth2.services.AccessTokenService;
import org.apache.cxf.rs.security.oauth2.services.AuthorizationService;
import org.apache.cxf.rs.security.oauth2.services.RedirectionBasedGrantService;
import org.apache.cxf.rs.security.oauth2.services.TokenIntrospectionService;
import org.apache.cxf.rs.security.oidc.idp.IdTokenResponseFilter;
import org.apache.cxf.rs.security.oidc.idp.OidcAuthorizationCodeService;
import org.apache.cxf.rs.security.oidc.idp.OidcConfigurationService;
import org.apache.cxf.rs.security.oidc.idp.OidcDynamicRegistrationService;
import org.apache.cxf.rs.security.oidc.idp.OidcHybridService;
import org.apache.cxf.rs.security.oidc.idp.OidcKeysService;
import org.apache.cxf.rs.security.oidc.idp.UserInfoService;
import org.gonzalad.cxf.fediz.jaxrs.provider.SpringViewResolverProvider;
import org.gonzalad.cxf.fediz.oidc.config.annotation.web.configuration.FedizOidcServerProperties;
import org.gonzalad.cxf.fediz.oidc.config.annotation.web.configuration.Signature;
import org.springframework.boot.context.embedded.Ssl;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.ViewResolver;

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

    private final ViewResolver viewResolver;

    private final LocaleResolver localeResolver;

    private List<JAXRSServerFactoryBean> endpoints = new ArrayList<>();

    private OAuthDataProvider oauthDataProvider;

    private AccessTokenService accessTokenService;

    private TokenIntrospectionService tokenIntrospectionService;

    private boolean tokenIntrospectionDisabled;

    private AuthorizationService authorizationService;

    private OAuth2EndpointBuilder oAuth2EndpointBuilder;

    private ClientRegistrationProviderBuilder clientRegistrationProviderBuilder;

    private JwkEndpointBuilder jwkEndpointBuilder;

    private IdpEndpointBuilder idpEndpointBuilder;

    private DiscoveryEndpointBuilder discoveryEndpointBuilder;

    private UserInfoEndpointBuilder userInfoEndpointBuilder;

    private UserConsoleEndpointBuilder userConsoleEndpointBuilder;

    private DynamicClientRegistrationEndpoint dynamicClientRegistrationEndpoint;

    private CxfBuilder cxfBuilder = new CxfBuilder();

    private FedizOidcServerProperties serverProperties;

    private ClaimsMapper claimsProvider;

    private List<String> grants = new ArrayList<>(Defaults.grants());

    public OidcServerBuilder(FedizOidcServerProperties serverProperties, Bus bus, ViewResolver viewResolver,
                             LocaleResolver localeResolver) {
        if (serverProperties == null) {
            throw new IllegalArgumentException("Parameter serverProperties is required");
        }
        this.oauthDataProvider = Defaults.authDataProvider(serverProperties);
        this.cxfBuilder.bus = bus;
        this.serverProperties = serverProperties;
        this.viewResolver = viewResolver;
        this.localeResolver = localeResolver;
        this.clientRegistrationProviderBuilder = new ClientRegistrationProviderBuilder();
        this.oAuth2EndpointBuilder = new OAuth2EndpointBuilder();
        this.jwkEndpointBuilder = new JwkEndpointBuilder();
        this.idpEndpointBuilder = new IdpEndpointBuilder();
        this.discoveryEndpointBuilder = new DiscoveryEndpointBuilder();
        this.userInfoEndpointBuilder = new UserInfoEndpointBuilder();
        this.userConsoleEndpointBuilder = new UserConsoleEndpointBuilder();
        this.dynamicClientRegistrationEndpoint = new DynamicClientRegistrationEndpoint();
    }

    public CxfBuilder cxf() {
        // be cautious : handle reentrancy...
        return cxfBuilder;
    }

    public UserInfoEndpointBuilder userInfo() {
         return userInfoEndpointBuilder;
    }

    public OAuth2EndpointBuilder oauth2() {
        // be cautious : handle reentrancy...
        return oAuth2EndpointBuilder;
    }

    public UserConsoleEndpointBuilder console() {
        // be cautious : handle reentrancy...
        return userConsoleEndpointBuilder;
    }

    public IdpEndpointBuilder idp() {
        // be cautious : handle reentrancy...
        return idpEndpointBuilder;
    }

    public JwkEndpointBuilder jwk() {
        // be cautious : handle reentrancy...
        return this.jwkEndpointBuilder;
    }

    public OidcServerBuilder grantHandlers(String... grantHandlers) {
        List<String> grants = new ArrayList<String>(Arrays.asList(grantHandlers));
        List<String> invalidGrants = grants.stream().filter(it -> !ACCEPTED_GRANTS.contains(it)).collect(Collectors.toList());
        if (invalidGrants.size() > 0) {
            throw new IllegalArgumentException(String.format("The following grants are not supported by fediz %s", invalidGrants));
        }
        this.grants = grants;
        return this;
    }

    public DiscoveryEndpointBuilder discovery() {
        return discoveryEndpointBuilder;
    }

    public ClientRegistrationProviderBuilder clientRegistration() {
        return clientRegistrationProviderBuilder;
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
        oidcServer.setBasePath(serverProperties.getBasePath());
        oidcServer.setOAuth2Endpoint(buildOAuth2Endpoint());
        oidcServer.setDiscoveryEndpoint(buildDiscoveryEndpoint());
        oidcServer.setJwkEndpoint(buildJwkEndpoint());
        oidcServer.setUserInfoEndpoint(buildUserInfoEndpoint());
        oidcServer.setIdpEndpoint(buildIdpEndpoint());
//        oidcServer.setClientRegistrationProvider(buildClientRegistrationProvider());
        oidcServer.setUserConsoleEndpoint(buildUserConsoleEndpoint());
        oidcServer.setDynamicClientRegistrationEndpoint(buildDynamicClientRegistrationEndpoint());
//        oidcServer.setAdditionalEndpoints(endpoints);
        return oidcServer;
    }

    private ClientRegistrationProvider buildClientRegistrationProvider() {
        ClientRegistrationProvider clientRegistrationProvider = clientRegistrationProviderBuilder.clientRegistrationProvider;
        if (clientRegistrationProvider == null) {
            if (oauthDataProvider instanceof ClientRegistrationProvider) {
                clientRegistrationProvider = (ClientRegistrationProvider) oauthDataProvider;
            }
        }
        if (clientRegistrationProvider == null) {
            if (!clientRegistrationProviderBuilder.clients.isEmpty()) {
                throw new IllegalStateException("Cannot create OIDC clients with null clientRegistrationProvider");
            }
        }
        for (Client client : clientRegistrationProviderBuilder.clients) {
            // TODO: shouldn't we wait for oidcServer to be fully initialized before creating clients ?
            clientRegistrationProvider.setClient(client);
        }
        return clientRegistrationProvider;
    }

    private JAXRSServerFactoryBean buildIdpEndpoint() {
        buildKeyManagementProperties(idpEndpointBuilder);
        // TODO handle viewProvider endpoint and bundle default resources inside jar (i.e use Spring Boot here ?)
        List<Object> defaultProviders = Arrays.asList(buildOAuthJsonProvider(), idpEndpointBuilder.viewProvider);
        List<Object> services = new ArrayList<>();
        Optional.ofNullable(buildAuthorizationService()).ifPresent(it -> services.add(it));
        Optional.ofNullable(buildLogoutService()).ifPresent(it -> services.add(it));
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
        return buildEndpoint(discoveryEndpointBuilder, buildDiscoveryService());
    }

    private JAXRSServerFactoryBean buildUserInfoEndpoint() {
        List<Object> defaultProviders = Arrays.asList(corsFilter(), new JsonMapObjectProvider());
        UserInfoService userInfoService = buildUserInfoService();
        return buildEndpoint(userInfoEndpointBuilder, userInfoService, Collections.emptyMap(), defaultProviders);
    }

    private JAXRSServerFactoryBean buildUserConsoleEndpoint() {
        List<Object> defaultProviders = Arrays.asList(defaultViewProvider());
        UserConsoleService userInfoService = buildUserConsoleService();
        return buildEndpoint(userConsoleEndpointBuilder, userInfoService, Collections.emptyMap(), defaultProviders);
    }

    private JAXRSServerFactoryBean buildDynamicClientRegistrationEndpoint() {
        List<Object> defaultProviders = Arrays.asList(new JsonMapObjectProvider());
        OidcDynamicRegistrationService registrationService = buildDynamicClientRegistrationService();
        return buildEndpoint(dynamicClientRegistrationEndpoint, registrationService, Collections.emptyMap(), defaultProviders);
    }

    private UserConsoleService buildUserConsoleService() {
        UserConsoleService userConsoleService = userConsoleEndpointBuilder.userConsoleService;
        if (!userConsoleEndpointBuilder.custom) {
            userConsoleService.getClientRegService().setDataProvider(oauthDataProvider);
            // TODO : rething the build part because we're either building multiple clientRegistrationProvider
            // or creating multiple times the same clients as of now
            ClientRegistrationProvider clientRegistrationProvider = buildClientRegistrationProvider();
            userConsoleService.getClientRegService().setClientProvider(clientRegistrationProvider);
            if (!userConsoleEndpointBuilder.customClientRegistrationService) {
                userConsoleService.getClientRegService().setHomeRealms(clientRegistrationProviderBuilder.homeRealms.stream().collect(Collectors.toMap(it -> it, it -> it)));
            }
        }
        return userConsoleService;
    }

    private OidcDynamicRegistrationService buildDynamicClientRegistrationService() {
        return dynamicClientRegistrationEndpoint.dynamicRegistrationService;
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
        UserInfoService userInfoService = userInfoEndpointBuilder.userInfoService;
        if (!userInfoEndpointBuilder.custom) {
            userInfoService.setOauthDataProvider(oauthDataProvider);
        }
        return userInfoService;
    }

    private AuthorizationService buildAuthorizationService() {
        if (authorizationService != null) {
            return authorizationService;
        }
        authorizationService = new AuthorizationService();
        List<RedirectionBasedGrantService> services = new ArrayList<>();
        if (idpEndpointBuilder.authorizationService.services.isEmpty()) {
            SubjectCreator subjectCreator = buildSubjectCreator();
            OidcAuthorizationCodeService authorizationCodeService = new OidcAuthorizationCodeService();
            authorizationCodeService.setDataProvider(oauthDataProvider);
            authorizationCodeService.setSkipAuthorizationWithOidcScope(idpEndpointBuilder.authorizationService.skipAuthorizationWithOidcScope);
            authorizationCodeService.setSubjectCreator(subjectCreator);
            authorizationCodeService.setScopesRequiringNoConsent(idpEndpointBuilder.authorizationService.scopesRequiringNoConsent);
            if (grants.contains(GRANT_IMPLICIT)) {
                authorizationCodeService.setCanSupportPublicClients(true);
            } else {
                authorizationCodeService.setCanSupportPublicClients(false);
            }
            if (grants.contains(GRANT_AUTHORIZATION_CODE)) {
                services.add(authorizationCodeService);
            }
            if (grants.contains(GRANT_IMPLICIT)) {
                OidcHybridService service = new OidcHybridService();
                service.setDataProvider(oauthDataProvider);
                service.setSubjectCreator(subjectCreator);
                service.setScopesRequiringNoConsent(idpEndpointBuilder.authorizationService.scopesRequiringNoConsent);
                service.setResponseFilter(buildIdTokenResponseFilter());
                service.setCodeService(authorizationCodeService);
                services.add(service);
            }
        } else {
            services.addAll(idpEndpointBuilder.authorizationService.services);
        }
        authorizationService.setServices(services);
        return authorizationService;
    }

    private LogoutService buildLogoutService() {
        IdpEndpointBuilder.LogoutServiceBuilder logoutBuilder = idpEndpointBuilder.logoutService;
        if (logoutBuilder.logoutService != null) {
            return logoutBuilder.logoutService;
        }
        // TODO if external idp, then create SAMLLogoutService
        LogoutService logoutService = new LogoutService();
        if (logoutBuilder.backChannelLogoutHandler != null) {
            logoutService.setBackChannelLogoutHandler(logoutBuilder.backChannelLogoutHandler);
        } else {
            BackChannelLogoutHandler backChannelLogoutHandler = new BackChannelLogoutHandler();
            backChannelLogoutHandler.setDataProvider(this.oauthDataProvider);
            logoutService.setBackChannelLogoutHandler(backChannelLogoutHandler);
        }
        logoutService.setDataProvider(oauthDataProvider);
        logoutService.setSubjectCreator(buildSubjectCreator());
        if (logoutBuilder.logoutHandlers.size() > 0) {
            logoutService.setLogoutHandlers(logoutBuilder.logoutHandlers);
        } else {
            TokenCleanupHandler tokenCleanupHandler = new TokenCleanupHandler();
            tokenCleanupHandler.setDataProvider(this.oauthDataProvider);
            logoutService.setLogoutHandlers(Arrays.asList(tokenCleanupHandler));
        }
        return logoutService;
    }

    private JAXRSServerFactoryBean buildJwkEndpoint() {
        buildKeyManagementProperties(jwkEndpointBuilder);
        List<Object> defaultProviders = Arrays.asList(corsFilter(), new JsonWebKeysProvider());
        OidcKeysService keyService = new OidcKeysService();
        keyService.setKeyServiceClient(jwkEndpointBuilder.keyServiceClient);
        return buildEndpoint(jwkEndpointBuilder, new OidcKeysService(), Collections.emptyMap(), defaultProviders);
    }

    private void buildKeyManagementProperties(EndpointBuilder endpointBuilder) {
        endpointBuilder.properties = buildKeyManagementProperties(endpointBuilder.properties);
    }

    /**
     * Transform Signature configuration to information usable
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
        Signature sig = serverProperties.getSignature();
        // TODO: 
        // Fediz appears to be able to use a keyClient (what is it ? appears interesting... could we support
        // that easily ?)
        Optional.ofNullable(sig.getKeyStore()).ifPresent(it -> newMap.put(RSSEC_KEY_STORE_FILE, sig.getKeyStore()));
        Optional.ofNullable(sig.getKeyStoreType()).ifPresent(it -> newMap.put(RSSEC_KEY_STORE_TYPE, sig.getKeyStoreType()));
        Optional.ofNullable(sig.getKeyStorePassword()).ifPresent(it -> newMap.put(RSSEC_KEY_STORE_PSWD, sig.getKeyStorePassword()));
        Optional.ofNullable(sig.getKeyAlias()).ifPresent(it -> newMap.put(RSSEC_KEY_STORE_ALIAS, sig.getKeyAlias()));
        Optional.ofNullable(sig.getKeyPassword()).ifPresent(it -> newMap.put(RSSEC_KEY_PSWD, sig.getKeyPassword()));
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
        OidcConfigurationService configurationService = this.discoveryEndpointBuilder.configurationService;
//        if (!discoveryEndpointBuilder.custom) {
//            configurationService.
//        }
        return configurationService;
    }

    private IdTokenResponseFilter buildIdTokenResponseFilter() {
        return new IdTokenResponseFilter();
    }

    private FedizSubjectCreator buildSubjectCreator() {
//        LocalSubjectCreator subjectCreator = new LocalSubjectCreator();
//        subjectCreator.setIdTokenIssuer(serverProperties.getIssuer());
//        subjectCreator.setSupportedClaims(supportedClaims);
//        subjectCreator.setStripPathFromIssuerUri(true);
        // TODO be able to configure idToken expiration
        FedizSubjectCreator subjectCreator = new FedizSubjectCreator();
        subjectCreator.setIdTokenIssuer(serverProperties.getIssuer());
        subjectCreator.setStripPathFromIssuerUri(true);
        if (claimsProvider != null) {
            subjectCreator.setClaimsProvider(claimsProvider);

        }
        return subjectCreator;
//        FedizSubjectCreator subjectCreator = new FedizSubjectCreator();
//        subjectCreator.setIdTokenIssuer(serverProperties.getIssuer());
//        subjectCreator.setSupportedClaims(supportedClaims);
//        return subjectCreator;
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
        accessTokenService.setBlockUnsecureRequests(oAuth2EndpointBuilder.tokenServiceBuilder.blockUnsecureRequests);
        accessTokenService.setClientIdProvider(oAuth2EndpointBuilder.tokenServiceBuilder.clientIdProvider);
        List<AccessTokenGrantHandler> grantHandlers = new ArrayList<>();
        if (oAuth2EndpointBuilder.tokenServiceBuilder.grantHandlers.isEmpty()) {
            if (grants.contains(GRANT_REFRESH)) {
                RefreshTokenGrantHandler refreshTokenGrantHandler = new RefreshTokenGrantHandler();
                refreshTokenGrantHandler.setDataProvider(oauthDataProvider);
                grantHandlers.add(refreshTokenGrantHandler);
            }
        } else {
            grantHandlers.addAll(oAuth2EndpointBuilder.tokenServiceBuilder.grantHandlers);
        }
        accessTokenService.setGrantHandlers(grantHandlers);
        return accessTokenService;
    }

    private Object defaultViewProvider() {
        SpringViewResolverProvider viewProvider = new SpringViewResolverProvider(OidcServerBuilder.this.viewResolver, localeResolver);
        viewProvider.setUseClassNames(true);
        viewProvider.setBeanName("model");
        viewProvider.setResourcePaths(Collections.singletonMap("/remove", "registeredClients"));
        viewProvider.setClassResources(Collections.singletonMap("org.apache.cxf.fediz.service.oidc.clients.InvalidRegistration", "invalidRegistration"));
        return viewProvider;
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
        private String address;
        private List<? extends Object> providers;
        private Map<String, Object> properties;
        private B parentBuilder;

        public EndpointBuilder(B parentBuilder) {
            this.parentBuilder = parentBuilder;
        }

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

        public B and() {
            return parentBuilder;
        }
    }

    public class JwkEndpointBuilder extends EndpointBuilder<OidcServerBuilder, JwkEndpointBuilder> {

        private WebClient keyServiceClient;

        public JwkEndpointBuilder() {
            super(OidcServerBuilder.this);
            super.address = "/jwk";
        }

        public JwkEndpointBuilder keyServiceClient(WebClient keyServiceClient) {
            this.keyServiceClient = keyServiceClient;
            return this;
        }
    }

    public class UserInfoEndpointBuilder extends EndpointBuilder<OidcServerBuilder, UserInfoEndpointBuilder> {

        private UserInfoService userInfoService = new UserInfoService();
        private boolean custom;

        public UserInfoEndpointBuilder() {
            super(OidcServerBuilder.this);
            super.address = "/users";
        }

        public UserInfoEndpointBuilder custom(UserInfoService userInfoService) {
            this.userInfoService = userInfoService;
            custom = true;
            return this;
        }

        public UserInfoEndpointBuilder jwsRequired(boolean jwsRequired) {
            this.userInfoService.setJwsRequired(jwsRequired);
            return this;
        }

        public UserInfoEndpointBuilder jweRequired(boolean jweRequired) {
            this.userInfoService.setJweRequired(jweRequired);
            return this;
        }
    }

    public class UserConsoleEndpointBuilder extends EndpointBuilder<OidcServerBuilder, UserConsoleEndpointBuilder> {

        private UserConsoleService userConsoleService;
        private boolean custom;
        private boolean customClientRegistrationService;

        public UserConsoleEndpointBuilder() {
            super(OidcServerBuilder.this);
            super.address = "/console";
            this.userConsoleService = new UserConsoleService();
            this.userConsoleService.setClientRegService(new ClientRegistrationService());
        }

        public UserConsoleEndpointBuilder custom(UserConsoleService userConsoleService) {
            this.userConsoleService = userConsoleService;
            custom = true;
            return this;
        }

        public UserConsoleEndpointBuilder clientRegistrationService(
                ClientRegistrationService clientRegistrationService) {
            this.userConsoleService.setClientRegService(clientRegistrationService);
            this.customClientRegistrationService = true;
            return this;
        }

        public UserConsoleEndpointBuilder additionalTLDs(List<String> additionalTLDs) {
            userConsoleService.getClientRegService().setAdditionalTLDs(additionalTLDs);
            return this;
        }

        public UserConsoleEndpointBuilder userRole(String userRole) {
            userConsoleService.getClientRegService().setUserRole(userRole);
            return this;
        }

        public UserConsoleEndpointBuilder clientScopes(List<String> clientScopes) {
            userConsoleService.getClientRegService().setClientScopes(clientScopes.stream().collect(Collectors.toMap(it -> it, it -> it)));
            return this;
        }

        public UserConsoleEndpointBuilder protectIdTokenWithClientSecret(boolean protectIdTokenWithClientSecret) {
            userConsoleService.getClientRegService().setProtectIdTokenWithClientSecret(protectIdTokenWithClientSecret);
            return this;
        }
    }

    public class DynamicClientRegistrationEndpoint extends EndpointBuilder<OidcServerBuilder, DynamicClientRegistrationEndpoint> {

        private OidcDynamicRegistrationService dynamicRegistrationService;
        private boolean custom;

        public DynamicClientRegistrationEndpoint() {
            super(OidcServerBuilder.this);
            super.address = "/connect";
            this.dynamicRegistrationService = new OidcDynamicRegistrationService();
        }

        public DynamicClientRegistrationEndpoint custom(OidcDynamicRegistrationService dynamicRegistrationService) {
            this.dynamicRegistrationService = dynamicRegistrationService;
            custom = true;
            return this;
        }

        public DynamicClientRegistrationEndpoint protectIdTokenWithClientSecret(
                boolean protectIdTokenWithClientSecret) {
            this.dynamicRegistrationService.setProtectIdTokenWithClientSecret(protectIdTokenWithClientSecret);
            return this;
        }

        public DynamicClientRegistrationEndpoint userRole(String userRole) {
            this.dynamicRegistrationService.setUserRole(userRole);
            return this;
        }

        public DynamicClientRegistrationEndpoint initialAccessToken(String initialAccessToken) {
            this.dynamicRegistrationService.setInitialAccessToken(initialAccessToken);
            return this;
        }
    }

    public class DiscoveryEndpointBuilder extends EndpointBuilder<OidcServerBuilder, JwkEndpointBuilder> {

        private OidcConfigurationService configurationService = new OidcConfigurationService();
        private boolean custom;

        public DiscoveryEndpointBuilder() {
            super(OidcServerBuilder.this);
            super.address = "/.well-known";
        }

        public DiscoveryEndpointBuilder custom(OidcConfigurationService configurationService) {
            this.configurationService = configurationService;
            this.custom = true;
            return this;
        }

        public DiscoveryEndpointBuilder backChannelLogoutSupported(boolean backChannelLogoutSupported) {
            this.configurationService.setBackChannelLogoutSupported(backChannelLogoutSupported);
            return this;
        }

        public DiscoveryEndpointBuilder dynamicRegistrationEndpointSupported(
                boolean dynamicRegistrationEndpointSupported) {
            this.configurationService.setDynamicRegistrationEndpointNotAvailable(!dynamicRegistrationEndpointSupported);
            return this;
        }

        public DiscoveryEndpointBuilder tokenRevocationEndpointSupported(boolean tokenRevocationEndpointSupported) {
            this.configurationService.setTokenRevocationEndpointNotAvailable(!tokenRevocationEndpointSupported);
            return this;
        }
    }

    public class OAuth2EndpointBuilder extends EndpointBuilder<OidcServerBuilder, OAuth2EndpointBuilder> {

        private TokenServiceBuilder tokenServiceBuilder = new TokenServiceBuilder();

        public OAuth2EndpointBuilder() {
            super(OidcServerBuilder.this);
            super.address = "/oauth2";
        }

        public TokenServiceBuilder tokenService() {
            return tokenServiceBuilder;
        }

        public class TokenServiceBuilder {

            public ClientIdProvider clientIdProvider;
            private boolean blockUnsecureRequests;
            private List<AccessTokenGrantHandler> grantHandlers = new ArrayList<>();

            public TokenServiceBuilder custom(
                    AccessTokenService accessTokenService) {
                OidcServerBuilder.this.accessTokenService = accessTokenService;
                return this;
            }

            public TokenServiceBuilder grantHandlers(AccessTokenGrantHandler... grantHandlers) {
                return grantHandlers(new ArrayList<AccessTokenGrantHandler>(Arrays.asList(grantHandlers)));
            }

            public TokenServiceBuilder grantHandlers(List<AccessTokenGrantHandler> grantHandlers) {
                this.grantHandlers.addAll(grantHandlers);
                return this;
            }

            public TokenServiceBuilder clientIdProvider(ClientIdProvider clientIdProvider) {
                this.clientIdProvider = clientIdProvider;
                return this;
            }

            public TokenServiceBuilder blockUnsecureRequests(boolean blockUnsecureRequests) {
                this.blockUnsecureRequests = blockUnsecureRequests;
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

        private Map<String, String> supportedScopes = new HashMap<>();

        public OAuthDataProviderBuilder custom(
                OAuthDataProvider oauthDataProvider) {
            OidcServerBuilder.this.oauthDataProvider = oauthDataProvider;
            return this;
        }

        public OAuthDataProviderBuilder supportedScopes(String... supportedScopes) {
            return supportedScopes(new ArrayList<String>(Arrays.asList(supportedScopes)));
        }

        public OAuthDataProviderBuilder supportedScopes(List<String> supportedScopes) {
            // todo handle scope label (i18n: use spring MessageSource)
            this.supportedScopes.putAll(supportedScopes.stream().collect(Collectors.toMap(it -> it, it -> it)));
            castToImpl("supportedScopes").setSupportedScopes(this.supportedScopes);
            return this;
        }

        public OAuthDataProviderBuilder defaultScopes(String... defaultScopes) {
            return defaultScopes(new ArrayList<String>(Arrays.asList(defaultScopes)));
        }

        public OAuthDataProviderBuilder defaultScopes(List<String> defaultScopes) {
            List<String> scopes = castToImpl("defaultScopes").getDefaultScopes();
            scopes.addAll(defaultScopes);
            castToImpl("defaultScopes").setDefaultScopes(scopes);
            return this;
        }

        public OAuthDataProviderBuilder invisibleToClientScopes(String... invisibleToClientScopes) {
            return invisibleToClientScopes(new ArrayList<String>(Arrays.asList(invisibleToClientScopes)));
        }

        public OAuthDataProviderBuilder invisibleToClientScopes(List<String> invisibleToClientScopes) {
            List<String> scopes = castToImpl("invisibleToClientScopes").getInvisibleToClientScopes();
            scopes.addAll(invisibleToClientScopes);
            castToImpl("invisibleToClientScopes").setInvisibleToClientScopes(scopes);
            return this;
        }

        public OAuthDataProviderBuilder recycleRefreshTokens(boolean recycleRefreshTokens) {
            castToImpl("recycleRefreshTokens").setRecycleRefreshTokens(recycleRefreshTokens);
            return this;
        }

        /**
         * Defaults to 1 hour.
         */
        public OAuthDataProviderBuilder accessTokenLifetime(long accessTokenLifetimeSec) {
            castToImpl("accessTokenLifetime").setAccessTokenLifetime(accessTokenLifetimeSec);
            return this;
        }

        /**
         * Eternal by default (-1).
         */
        public OAuthDataProviderBuilder refreshTokenLifetime(long refreshTokenLifetimeSec) {
            castToImpl("refreshTokenLifetime").setRefreshTokenLifetime(refreshTokenLifetimeSec);
            return this;
        }

        public OAuthDataProviderBuilder useJwtFormatForAccessTokens(boolean useJwtFormatForAccessTokens) {
            castToImpl("useJwtFormatForAccessTokens").setUseJwtFormatForAccessTokens(useJwtFormatForAccessTokens);
            return this;
        }

        public OAuthDataProviderBuilder authenticationStrategy(ProviderAuthenticationStrategy authenticationStrategy) {
            castToImpl("authenticationStrategy").setAuthenticationStrategy(authenticationStrategy);
            return this;
        }

        public OAuthDataProviderBuilder jwtAccessTokenProducer(OAuthJoseJwtProducer jwtAccessTokenProducer) {
            castToImpl("jwtAccessTokenProducer").setJwtAccessTokenProducer(jwtAccessTokenProducer);
            return this;
        }

        public OAuthDataProviderBuilder jwtAccessTokenClaimMap(Map<String, String> jwtAccessTokenClaimMap) {
            castToImpl("jwtAccessTokenClaimMap").setJwtAccessTokenClaimMap(jwtAccessTokenClaimMap);
            return this;
        }

        public OAuthDataProviderBuilder supportPreauthorizedTokens(boolean supportPreauthorizedTokens) {
            castToImpl("supportPreauthorizedTokens").setSupportPreauthorizedTokens(supportPreauthorizedTokens);
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

    public class ClientRegistrationProviderBuilder {

        private ClientRegistrationProvider clientRegistrationProvider;

        private List<Client> clients = new ArrayList<>();

        /**
         * TODO will need to create Map with homeId -> label (label dynamically
         * resolved from Spring MessageSourceResolvable)
         */
        private List<String> homeRealms = new ArrayList<>();

        public ClientRegistrationProviderBuilder custom(
                ClientRegistrationProvider clientRegistrationProvider) {
            this.clientRegistrationProvider = clientRegistrationProvider;
            return this;
        }

        public ClientRegistrationProviderBuilder clients(Client... clients) {
            return clients(Arrays.asList(clients));
        }

        public ClientRegistrationProviderBuilder clients(List<Client> clients) {
            clients.forEach(it -> validate(it));
            this.clients.addAll(clients);
            return this;
        }

        public ClientRegistrationProviderBuilder homeRealms(String... homeRealms) {
            return homeRealms(Arrays.asList(homeRealms));
        }

        public ClientRegistrationProviderBuilder homeRealms(List<String> homeRealms) {
            this.homeRealms.addAll(homeRealms);
            return this;
        }

        private void validate(Client client) {
            if (client.getClientId() == null) {
                throw new IllegalArgumentException("Cannot register client: clientId is required");
            }
            if (client.getClientId().contains(":")) {
                throw new IllegalArgumentException(String.format("Cannot register client '%s': clientId must not contain ':'", client.getClientId()));
            }
            if (client.getClientSecret() != null && client.getClientSecret().contains(":")) {
                throw new IllegalArgumentException(String.format("Cannot register client '%s': clientSecret must not contain ':'", client.getClientId()));
            }
        }

        public OidcServerBuilder and() {
            return OidcServerBuilder.this;
        }
    }

    public class IdpEndpointBuilder extends EndpointBuilder<OidcServerBuilder, OAuth2EndpointBuilder> {

        private Object viewProvider;

        private AuthorizationServiceBuilder authorizationService = new AuthorizationServiceBuilder();

        private LogoutServiceBuilder logoutService = new LogoutServiceBuilder();

        public IdpEndpointBuilder() {
            super(OidcServerBuilder.this);
            super.address = "/idp";
            viewProvider = defaultViewProvider();
        }

        public IdpEndpointBuilder viewResolver(Object viewResolver) {
            this.viewProvider = viewResolver;
            return this;
        }

        public IdpEndpointBuilder claimsProvider(ClaimsMapper claimsProvider) {
            OidcServerBuilder.this.claimsProvider = claimsProvider;
            return this;
        }

        public AuthorizationServiceBuilder authorizationService() {
            return authorizationService;
        }

        public LogoutServiceBuilder logoutService() {
            return logoutService;
        }

        // TODO add logoutBuilder...

        public class AuthorizationServiceBuilder {

            private List<RedirectionBasedGrantService> services = new ArrayList<>();

            private List<String> scopesRequiringNoConsent = Defaults.scopesRequiringNoConsent();

            private boolean skipAuthorizationWithOidcScope;

            public AuthorizationServiceBuilder services(RedirectionBasedGrantService... services) {
                return services(Arrays.asList(services));
            }

            public AuthorizationServiceBuilder services(List<RedirectionBasedGrantService> services) {
                this.services.addAll(services);
                return this;
            }

            public AuthorizationServiceBuilder scopesRequiringNoConsent(String... scopesRequiringNoConsent) {
                this.scopesRequiringNoConsent = new ArrayList<String>(Arrays.asList(scopesRequiringNoConsent));
                return this;
            }

            public AuthorizationServiceBuilder skipAuthorizationWithOidcScope(boolean skip) {
                this.skipAuthorizationWithOidcScope = skip;
                return this;
            }

            public IdpEndpointBuilder and() {
                return IdpEndpointBuilder.this;
            }
        }

        public class LogoutServiceBuilder {

            private LogoutService logoutService;

            private List<LogoutHandler> logoutHandlers = new ArrayList<>();

            private BackChannelLogoutHandler backChannelLogoutHandler;

            public LogoutServiceBuilder custom(LogoutService logoutService) {
                this.logoutService = logoutService;
                return this;
            }

            public LogoutServiceBuilder logoutHandlers(LogoutHandler... handlers) {
                return logoutHandlers(Arrays.asList(handlers));
            }

            public LogoutServiceBuilder logoutHandlers(List<LogoutHandler> handlers) {
                this.logoutHandlers.addAll(handlers);
                return this;
            }

            public LogoutServiceBuilder backChannelLogoutHandler(BackChannelLogoutHandler backChannelLogoutHandler) {
                this.backChannelLogoutHandler = backChannelLogoutHandler;
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
