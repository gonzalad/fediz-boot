package org.gonzalad.cxf.fediz.idp.config.annotation.web;

import org.apache.cxf.fediz.service.idp.service.ConfigService;
import org.apache.cxf.fediz.service.idp.service.ConfigServiceSpring;
import org.apache.cxf.fediz.service.idp.service.jpa.ConfigServiceJPA;

/**
 * @author agonzalez
 */
public class IdpServerBuilder {

    private String realm;

    public IdpServerBuilder realm(String realm) {
        this.realm = realm;
        return this;
    }

    public class ConfigServiceBuilder {
        private static final String TYPE_JPA = "jpa";
        private static final String TYPE_MEMORY = "memory";
        private ConfigService configService;

        public ConfigServiceBuilder type(String type) {
            switch (type) {
                case TYPE_JPA:
                    this.configService = new ConfigServiceJPA();
                    break;
                case TYPE_MEMORY:
                    this.configService = new ConfigServiceSpring();
                    break;
                default:
                    throw new IllegalArgumentException(String.format("type '%s' not handled - only jpa and memory"));
            }
            return this;
        }

        public ConfigServiceBuilder type(String type) {
            switch (type) {
                case TYPE_JPA:
                    this.configService = new ConfigServiceJPA();
                    break;
                case TYPE_MEMORY:
                    this.configService = new ConfigServiceSpring();
                    break;
                default:
                    throw new IllegalArgumentException(String.format("type '%s' not handled - only jpa and memory"));
            }
        }

    }
}
