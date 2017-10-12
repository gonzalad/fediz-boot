package org.gonzalad.cxf.fediz.sts.config.annotation.web.configuration;

import org.springframework.boot.context.embedded.Ssl;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * @author agonzalez
 */
@ConfigurationProperties(prefix = "fediz.sts", ignoreUnknownFields = true)
public class FedizStsServerProperties {

    @NestedConfigurationProperty
    private Ssl ssl;

    private String issuer;

    private String basePath;

    public Ssl getSsl() {
        return ssl;
    }

    public void setSsl(Ssl ssl) {
        this.ssl = ssl;
    }

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
}
