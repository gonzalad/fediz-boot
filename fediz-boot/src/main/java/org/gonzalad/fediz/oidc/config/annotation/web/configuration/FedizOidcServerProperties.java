package org.gonzalad.fediz.oidc.config.annotation.web.configuration;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.embedded.Ssl;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * @author agonzalez
 */
@ConfigurationProperties(prefix = "fediz.oidc", ignoreUnknownFields = true)
public class FedizOidcServerProperties implements InitializingBean {

    public static final long DEFAULT_ACCESS_TOKEN_LIFETIME = 1800;
    private String issuer;
    private String basePath;
    private Long accessTokenLifetime;
    @NestedConfigurationProperty
    private Ssl ssl;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getBasePath() {
        return basePath;
    }

    public void setBasePath(String basePath) {
        this.basePath = basePath;
    }

    public Long getAccessTokenLifetime() {
        return accessTokenLifetime;
    }

    public void setAccessTokenLifetime(Long accessTokenLifetime) {
        this.accessTokenLifetime = accessTokenLifetime;
    }

    public Ssl getSsl() {
        return ssl;
    }

    public void setSsl(Ssl ssl) {
        this.ssl = ssl;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("FedizOidcServerProperties{");
        sb.append("issuer='").append(issuer).append('\'');
        sb.append(", basePath='").append(basePath).append('\'');
        sb.append(", accessTokenLifetime='").append(accessTokenLifetime).append('\'');
        sb.append('}');
        return sb.toString();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (getIssuer() == null || getIssuer().isEmpty()) {
            throw new IllegalStateException("Required property fediz.oidc.issuer missing");
        }
    }
}
