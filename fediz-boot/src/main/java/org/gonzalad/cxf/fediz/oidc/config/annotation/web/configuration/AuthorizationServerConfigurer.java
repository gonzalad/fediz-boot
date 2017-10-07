package org.gonzalad.cxf.fediz.oidc.config.annotation.web.configuration;

import org.gonzalad.cxf.fediz.oidc.config.annotation.web.builders.OidcServerBuilder;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Configurer interface for <code>@EnableAuthorizationServer</code> classes. Implement this interface to adjust the configuration
 * of your Fediz OIDC Authorization Server.
 * <p>
 * When multiple instances of this interface are provided, then the last one wins (the configurers are sorted by @{@link Order}).
 *
 * @author agonzalez
 */
public interface AuthorizationServerConfigurer {

    /**
     * Tune Authorization Server specific configuration. The defaults should work oob..
     *
     * @param authorizationServer configurer for the authorization server
     * @throws Exception if there is a problem
     */
    void configure(OidcServerBuilder authorizationServer) throws Exception;

    /**
     * Use this to configure the access rules for secure resources. By default all resources (TODO except what ?)
     * are protected.
     *
     * @param http the current http filter configuration
     * @throws Exception if there is a problem
     */
    void configure(HttpSecurity http) throws Exception;
}
