package org.gonzalad.cxf.fediz.sts.config.annotation.web.builders;

import org.apache.cxf.Bus;
import org.apache.cxf.jaxws.EndpointImpl;

/**
 * @author agonzalez
 */
public class StsServer {

    private Bus bus;

    private String basePath;

    private EndpointImpl stsEndpoint;

    private EndpointImpl stsEndpointWithProperties;

    public void setBasePath(String basePath) {
        this.basePath = basePath != null ? basePath : "";
    }

    public void setBus(Bus bus) {
        this.bus = bus;
    }

    public void start() {
    }

    public void stop() {
    }

    public void setStsEndpoint(EndpointImpl stsEndpoint) {
        this.stsEndpoint = stsEndpoint;
    }

    public void setStsEndpointWithProperties(EndpointImpl stsEndpointWithProperties) {
        this.stsEndpointWithProperties = stsEndpointWithProperties;
    }
}
