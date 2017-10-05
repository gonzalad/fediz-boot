package org.gonzalad.fediz.oidc.config.annotation.web.builders;

import java.util.Optional;

import org.apache.cxf.Bus;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;

/**
 * @author agonzalez
 */
public class OidcServer {
    private OAuthDataProvider authDataProvider;
    private JAXRSServerFactoryBean discoveryEndpoint;
    private JAXRSServerFactoryBean jwkEndpoint;
    private JAXRSServerFactoryBean userInfoEndpoint;
    private Bus bus;
    private JAXRSServerFactoryBean oauth2Endpoint;
    private JAXRSServerFactoryBean idpEndpoint;


    public void setBus(Bus bus) {
        this.bus = bus;
    }

    public void setAuthDataProvider(OAuthDataProvider authDataProvider) {
        this.authDataProvider = authDataProvider;
    }

    public void setDiscoveryEndpoint(JAXRSServerFactoryBean discoveryEndpoint) {
        this.discoveryEndpoint = discoveryEndpoint;
    }

    public void setJwkEndpoint(JAXRSServerFactoryBean jwkEndpoint) {
        this.jwkEndpoint = jwkEndpoint;
    }

    public void setUserInfoEndpoint(JAXRSServerFactoryBean userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public void setOAuth2Endpoint(JAXRSServerFactoryBean oauth2Endpoint) {
        this.oauth2Endpoint = oauth2Endpoint;
    }

    public void start() {
        Optional.ofNullable(discoveryEndpoint).ifPresent(it -> it.init());
        Optional.ofNullable(jwkEndpoint).ifPresent(it -> it.init());
        Optional.ofNullable(userInfoEndpoint).ifPresent(it -> it.init());
        Optional.ofNullable(oauth2Endpoint).ifPresent(it -> it.init());
        Optional.ofNullable(idpEndpoint).ifPresent(it -> it.init());
    }

    public void stop() {

    }

    public void setIdpEndpoint(JAXRSServerFactoryBean idpEndpoint) {
        this.idpEndpoint = idpEndpoint;
    }
}
