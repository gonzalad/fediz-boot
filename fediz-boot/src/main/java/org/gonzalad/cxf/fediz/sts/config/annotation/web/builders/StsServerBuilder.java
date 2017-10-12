package org.gonzalad.cxf.fediz.sts.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.cxf.Bus;
import org.apache.cxf.fediz.service.sts.FedizSAMLDelegationHandler;
import org.apache.cxf.fediz.service.sts.FedizX509DelegationHandler;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.claims.ClaimsAttributeStatementProvider;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsManager;
import org.apache.cxf.sts.event.STSEventListener;
import org.apache.cxf.sts.event.map.EventMapper;
import org.apache.cxf.sts.event.map.MapEventLogger;
import org.apache.cxf.sts.operation.AbstractOperation;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.operation.TokenValidateOperation;
import org.apache.cxf.sts.service.ServiceMBean;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.sts.token.delegation.TokenDelegationHandler;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.ConditionsProvider;
import org.apache.cxf.sts.token.provider.DefaultConditionsProvider;
import org.apache.cxf.sts.token.provider.DefaultSubjectProvider;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.SubjectProvider;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.sts.token.provider.jwt.JWTTokenProvider;
import org.apache.cxf.sts.token.realm.RealmProperties;
import org.apache.cxf.sts.token.validator.SAMLTokenValidator;
import org.apache.cxf.sts.token.validator.TokenValidator;
import org.apache.cxf.sts.token.validator.X509TokenValidator;
import org.apache.cxf.sts.token.validator.jwt.JWTTokenValidator;
import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.dom.validate.Validator;
import org.gonzalad.cxf.fediz.sts.callback.SimpleKeystoreCallbackHandler;
import org.gonzalad.cxf.fediz.sts.config.annotation.web.configuration.FedizStsServerProperties;
import org.gonzalad.cxf.fediz.sts.spring.SpringSecurityValidatorAdapter;
import org.springframework.security.authentication.AuthenticationManager;

/**
 * Sts is so configurable that I don't know how to do a good builder.
 * <p>
 * Anyway, let's have a minimalistic one...
 *
 * @author agonzalez
 */
public class StsServerBuilder {

    private final FedizStsServerProperties serverProperties;
    private List<ClaimsHandler> claimsHandlers = new ArrayList<>();
    private Map<String, RealmProperties> realmMap = new HashMap<>();

    private CxfBuilder cxfBuilder = new CxfBuilder();
    private Validator validator;

    public StsServerBuilder(FedizStsServerProperties serverProperties) {
        this.serverProperties = serverProperties;
    }

    public StsServerBuilder claimHandlers(ClaimsHandler... claimsHandler) {
        return claimsHandlers(Arrays.asList(claimsHandler));
    }

    public StsServerBuilder validator(Validator validator) {
        this.validator = validator;
        return this;
    }

    public StsServerBuilder authenticationProvider(AuthenticationManager authenticationManager) {
        this.validator = new SpringSecurityValidatorAdapter(authenticationManager);
        return this;
    }

    public StsServerBuilder claimsHandlers(List<ClaimsHandler> claimsHandlers) {
        this.claimsHandlers.addAll(claimsHandlers);
        return this;
    }

    public StsServerBuilder realm(RealmProperties... realm) {
        return realms(Arrays.asList(realm));
    }

    public StsServerBuilder realms(List<RealmProperties> realms) {
        realms.forEach(it -> realmMap.put(it.getName(), it));
        return this;
    }

    public CxfBuilder cxf() {
        return cxfBuilder;
    }

    public StsServer build() throws Exception {
        StsServer stsServer = new StsServer();
        stsServer.setStsEndpoint(buildSTSEndpoint());
        stsServer.setStsEndpointWithProperties(buildSTSEndpointWithProperties());
        return stsServer;
    }

    private EndpointImpl buildSTSEndpoint() throws Exception {
        // see http://cxf.apache.org/docs/jax-ws-configuration.html#JAX-WSConfiguration-ConfiguretheJAXWSServerUsingSpringBoot
        EndpointImpl endpoint = new EndpointImpl(cxfBuilder.bus, buildSecurityTokenServiceProvider());
        endpoint.publish("/STSServiceTransport");
        return endpoint;
    }

    /**
     * Wwhy do we need both buildSTSEndpoint and buildSTSEndpointWithProperties ?
     */
    private EndpointImpl buildSTSEndpointWithProperties() throws Exception {
        // see http://cxf.apache.org/docs/jax-ws-configuration.html#JAX-WSConfiguration-ConfiguretheJAXWSServerUsingSpringBoot
        EndpointImpl endpoint = new EndpointImpl(cxfBuilder.bus, buildSecurityTokenServiceProvider());
        endpoint.publish("/STSServiceTransport");
        if (validator == null) {
            throw new IllegalStateException("One of authenticationManager or validator is required");
        }
        Map<String, Object> properties = new HashMap<>();
        properties.put("ws-security.ut.validator", validator);
        properties.put("ws-security.return.security.error", "true");
        endpoint.setProperties(properties);
        return endpoint;
    }

    private SecurityTokenServiceProvider buildSecurityTokenServiceProvider() throws Exception {
        SecurityTokenServiceProvider serviceProvider = new SecurityTokenServiceProvider();
        serviceProvider.setIssueOperation(buildTokenIssueOperation());
        serviceProvider.setValidateOperation(buildTokenValidateOperation());
        return serviceProvider;
    }

    private StaticSTSProperties buildSTSProperties() {
        StaticSTSProperties stsProperties = new StaticSTSProperties();
        stsProperties.setCallbackHandler(new SimpleKeystoreCallbackHandler(serverProperties.getSsl().getKeyPassword()));
        stsProperties.setIssuer(serverProperties.getIssuer());
        Map<String, Object> signatureProperties = new HashMap<>();
        signatureProperties.put("org.apache.ws.security.crypto.provider", Merlin.class.getName());
        signatureProperties.put("org.apache.ws.security.crypto.merlin.keystore.type", serverProperties.getSsl().getKeyStoreType());
        signatureProperties.put("org.apache.ws.security.crypto.merlin.keystore.password", serverProperties.getSsl().getKeyStorePassword());
        signatureProperties.put("org.apache.ws.security.crypto.merlin.keystore.alias", serverProperties.getSsl().getKeyAlias());
        signatureProperties.put("org.apache.ws.security.crypto.merlin.keystore.file", serverProperties.getSsl().getKeyStore());
        stsProperties.setSignatureCryptoProperties(signatureProperties);
        stsProperties.setRelationships(Collections.emptyList());
        return stsProperties;
    }

    private TokenIssueOperation buildTokenIssueOperation() {
        TokenIssueOperation issueOperation = setUpOperation(new TokenIssueOperation());
        issueOperation.setTokenProviders(buildTokenProviders());
        issueOperation.setServices(buildTransportServices());
        issueOperation.setClaimsManager(buildClaimsManager());
        issueOperation.setDelegationHandlers(buildDelegationHandlers());
        issueOperation.setAllowCustomContent(true);
        return issueOperation;
    }

    private TokenValidateOperation buildTokenValidateOperation() {
        return setUpOperation(new TokenValidateOperation());
    }

    private <E extends AbstractOperation> E setUpOperation(E operation) {
        operation.setStsProperties(buildSTSProperties());
        operation.setEventListener(buildEventListener());
        operation.setTokenValidators(buildTokenValidators());
        return operation;
    }

    private List<TokenDelegationHandler> buildDelegationHandlers() {
        return Arrays.asList(new FedizSAMLDelegationHandler(), new FedizX509DelegationHandler());
    }

    private STSEventListener buildEventListener() {
        return new EventMapper(new MapEventLogger());
    }

    private List<TokenValidator> buildTokenValidators() {
        return Arrays.asList(new SAMLTokenValidator(), new X509TokenValidator(), new JWTTokenValidator());
    }

    private ClaimsManager buildClaimsManager() {
        ClaimsManager claimsManager = new ClaimsManager();
        claimsManager.setClaimHandlers(claimsHandlers);
        return claimsManager;
    }

    private List<ServiceMBean> buildTransportServices() {
        return Arrays.asList(buildTransportService());
    }

    private ServiceMBean buildTransportService() {
        StaticService service = new StaticService();
        service.setEndpoints(Arrays.asList(".*"));
        return service;
    }


    private List<TokenProvider> buildTokenProviders() {
        return Arrays.asList(buildSAMLTokenProvider(), buildJwtTokenProvider());
    }

    private TokenProvider buildJwtTokenProvider() {
        JWTTokenProvider tokenProvider = new JWTTokenProvider();
        tokenProvider.setRealmMap(realmMap);
        return tokenProvider;
    }

    private TokenProvider buildSAMLTokenProvider() {
        SAMLTokenProvider tokenProvider = new SAMLTokenProvider();
        tokenProvider.setAttributeStatementProviders(buildAttributeStatementProvider());
        tokenProvider.setRealmMap(realmMap);
        tokenProvider.setConditionsProvider(buildConditionProvider());
        tokenProvider.setSubjectProvider(buildSubjectProvider());
        return tokenProvider;
    }

    private SubjectProvider buildSubjectProvider() {
        DefaultSubjectProvider subjectProvider = new DefaultSubjectProvider();
        subjectProvider.setSubjectNameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        return subjectProvider;
    }

    private ConditionsProvider buildConditionProvider() {
        DefaultConditionsProvider conditionsProvider = new DefaultConditionsProvider();
        conditionsProvider.setLifetime(1200);
        conditionsProvider.setAcceptClientLifetime(true);
        return conditionsProvider;
    }

    private List<AttributeStatementProvider> buildAttributeStatementProvider() {
        return Arrays.asList(new ClaimsAttributeStatementProvider());
    }

    public class CxfBuilder {

        private Bus bus;

        private String basePath;

        public CxfBuilder basePath(String basePath) {
            this.basePath = basePath;
            return this;
        }

        public CxfBuilder bus(Bus bus) {
            this.bus = bus;
            return this;
        }

        public StsServerBuilder and() {
            return StsServerBuilder.this;
        }
    }
//
//    public class StsProviderBuilder {
//
//        private OperationBuilder operationBuilder;
//
//        public OperationBuilder operation() {
//            if (operationBuilder == null) {
//                operationBuilder = new OperationBuilder();
//            }
//            return operationBuilder;
//        }
//
//        public StsServerBuilder and() {
//            return StsServerBuilder.this;
//        }
//
//        public class OperationBuilder {
//
//            private IssueOperationBuilder issueOperationBuilder;
//
//            private OperationBuilder operationBuilder;
//
//            public IssueOperationBuilder issue() {
//
//            }
//
//            public StsProviderBuilder and() {
//                return StsProviderBuilder.this;
//            }
//
//        }
//    }

}
