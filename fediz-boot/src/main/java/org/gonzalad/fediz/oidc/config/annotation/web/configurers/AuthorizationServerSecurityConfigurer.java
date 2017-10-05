package org.gonzalad.fediz.oidc.config.annotation.web.configurers;

import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * @author agonzalez
 */
public final class AuthorizationServerSecurityConfigurer extends
        SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private String basePath;

    public AuthorizationServerSecurityConfigurer basePath(String basePath) {
        this.basePath = basePath;
        return this;
    }

    public AuthorizationServerSecurityConfigurer cxf() {
        throw new NoSuchMethodError("Unimplemented method");
    }

    public OAuthDataProviderConfigurer oauthDataProvider() {
        return new OAuthDataProviderConfigurer();
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
//        AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
//        resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
//        resourcesServerFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
//        resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);
//        if (eventPublisher != null) {
//            resourcesServerFilter.setAuthenticationEventPublisher(eventPublisher);
//        }
//        if (tokenExtractor != null) {
//            resourcesServerFilter.setTokenExtractor(tokenExtractor);
//        }
//        resourcesServerFilter = postProcess(resourcesServerFilter);
//        resourcesServerFilter.setStateless(stateless);
//
//        // @formatter:off
//        http
//                .authorizeRequests().expressionHandler(expressionHandler)
//                .and()
//                .addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
//                .exceptionHandling()
//                .accessDeniedHandler(accessDeniedHandler)
//                .authenticationEntryPoint(authenticationEntryPoint);
//        // @formatter:on
    }

    public class OAuthDataProviderConfigurer {

        private OAuthDataProvider oauthDataProvider;

        public OAuthDataProviderConfigurer custom(OAuthDataProvider oauthDataProvider) {
            this.oauthDataProvider = oauthDataProvider;
            return this;
        }

        public AuthorizationServerSecurityConfigurer and() {
            return AuthorizationServerSecurityConfigurer.this;
        }
    }
}
