package org.gonzalad.fediz.oidc.config.annotation.web.configuration;

import java.util.Collections;
import java.util.List;

import org.gonzalad.fediz.oidc.config.annotation.web.builders.OidcServerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author agonzalez
 */
@Configuration
public class AuthorizationServerConfiguration extends WebSecurityConfigurerAdapter implements Ordered {

    @Autowired(required = false)
    private List<AuthorizationServerConfigurer> configurers = Collections.emptyList();

    @Autowired
    private ServerProperties serverProperties;

    private OidcServerBuilder authorizationServerBuilder;

    private int order = 2;

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
        authorizationServerBuilder = new OidcServerBuilder(serverProperties);
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
        // TODO init oidcServer
        authorizationServerBuilder.getEndpoints()

    }
}
