package org.gonzalad.fediz.oidc.config.annotation.web.configuration;

import java.util.Collections;
import java.util.List;

import org.apache.cxf.Bus;
import org.gonzalad.fediz.oidc.config.annotation.web.builders.OidcServer;
import org.gonzalad.fediz.oidc.config.annotation.web.builders.OidcServerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import static org.gonzalad.fediz.oidc.config.annotation.web.configuration.FedizOidcServerProperties.DEFAULT_ACCESS_TOKEN_LIFETIME;

/**
 * @author agonzalez
 */
@Configuration
@EnableConfigurationProperties(FedizOidcServerProperties.class)
public class AuthorizationServerConfiguration extends WebSecurityConfigurerAdapter implements Ordered {

    @Autowired(required = false)
    private List<AuthorizationServerConfigurer> configurers = Collections.emptyList();

    private FedizOidcServerProperties oidcServerProperties;


    @Autowired
    private ServerProperties serverProperties;

    @Autowired(required = false)
    private Bus bus;

    private OidcServerBuilder authorizationServerBuilder;

    private int order = 2;

    public AuthorizationServerConfiguration(FedizOidcServerProperties oidcServerProperties) {
        if (oidcServerProperties == null) {
            throw new IllegalArgumentException("Parameter oidcServerProperties is required");
        }
        this.oidcServerProperties = oidcServerProperties;
    }

    public int getOrder() {
        return order;
    }

    // TODO : create httpChain and OidcServer from single Builder
//    @Bean
//    public OidcServer objectProduit() {
//        return builder.build();
//    }
//
//    @Autowired
//    public void setConfigurers(List<AuthorizationServerSecurityConfigurer> configurers) {
//        builder = objectPostProcessor
//                .postProcess(new Builder(objectPostProcessor));
//        for (Configurer configurer: configurers) {
//            builder.apply(configurer);
//        }
//    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        oidcServerProperties.setAccessTokenLifetime(serverProperties.getSession().getTimeout() != null ? serverProperties.getSession().getTimeout() : DEFAULT_ACCESS_TOKEN_LIFETIME);
        if (oidcServerProperties.getJwk().getLocalStore() == null) {
            // if missing, we take general ssl configuration from Spring
            oidcServerProperties.getJwk().setLocalStore(serverProperties.getSsl());
            if (oidcServerProperties.getJwk().getLocalStore() == null) {
                throw new IllegalStateException("Configuration property fediz.oidc.jwk.local-store or server.ssl missing");
            }
        }
        authorizationServerBuilder = new OidcServerBuilder(oidcServerProperties, bus);
        for (AuthorizationServerConfigurer configurer : configurers) {
            configurer.configure(authorizationServerBuilder);
        }
        if (configurers.isEmpty()) {
            // Add anyRequest() last as a fall back in case user
            // didn't configure anything
            http.authorizeRequests().anyRequest().authenticated();
        }
    }

    @Override
    public void init(WebSecurity web) throws Exception {
        super.init(web);
        OidcServer oidcServer = authorizationServerBuilder.build();
        oidcServer.start();
    }
}
