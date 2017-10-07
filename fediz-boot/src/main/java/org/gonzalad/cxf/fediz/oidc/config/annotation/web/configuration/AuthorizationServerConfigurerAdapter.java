package org.gonzalad.cxf.fediz.oidc.config.annotation.web.configuration;

import org.gonzalad.cxf.fediz.oidc.config.annotation.web.builders.OidcServerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Default implementation for AuthorizationServerConfigurer.
 * <p>
 * Access to all resources require users to be authenticated.
 *
 * @author agonzalez
 */
public class AuthorizationServerConfigurerAdapter implements AuthorizationServerConfigurer {
    public void configure(OidcServerBuilder authorizationServer) throws Exception {
    }

    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
    }
}
