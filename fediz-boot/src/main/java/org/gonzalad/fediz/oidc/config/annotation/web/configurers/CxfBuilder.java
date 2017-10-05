package org.gonzalad.fediz.oidc.config.annotation.web.configurers;

import org.apache.cxf.Bus;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;

/**
 * @author agonzalez
 */
public class CxfBuilder<O, B extends SecurityBuilder<O>> implements SecurityConfigurer<O, B> {

    private Bus bus;

    private B builder;

    public CxfBuilder(B builder) {
        if (builder == null) {
            throw new IllegalArgumentException("Parmeter builder is required");
        }
        this.builder = builder;
    }

    public void init(B builder) throws Exception {
    }

    public void configure(B builder) throws Exception {
    }

    public CxfBuilder<O, B> bus(Bus bus) {
        this.bus = bus;
        return this;
    }

    public B and() {
        return builder;
    }
}
