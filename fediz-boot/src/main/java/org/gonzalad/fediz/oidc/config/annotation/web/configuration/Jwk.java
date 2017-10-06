package org.gonzalad.fediz.oidc.config.annotation.web.configuration;

import org.springframework.boot.context.embedded.Ssl;

/**
 * @author agonzalez
 */
public class Jwk {

    private Ssl localStore;

    public Ssl getLocalStore() {
        return localStore;
    }

    public void setLocalStore(Ssl localStore) {
        this.localStore = localStore;
    }
}
