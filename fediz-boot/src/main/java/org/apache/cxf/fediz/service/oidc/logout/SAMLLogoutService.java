package org.apache.cxf.fediz.service.oidc.logout;

import java.net.URI;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;

/**
 * This logout service should be used whenever oidc is a SAML RP
 * and is part of SAML logout workflow.
 */
public class SAMLLogoutService extends LogoutService {

    private String relativeIdpLogoutUri;

    /**
     * Redirects to Client Application once logout is finished
     */
    @Override
    protected Response redirect(Client client, MultivaluedMap<String, String> params) {
        // Redirect to the core IDP
        URI idpLogoutUri = getAbsoluteIdpLogoutUri(client, params);
        return Response.seeOther(idpLogoutUri).build();
    }

    private URI getAbsoluteIdpLogoutUri(Client client, MultivaluedMap<String, String> params) {
        UriBuilder ub = getMessageContext().getUriInfo().getAbsolutePathBuilder();
        ub.path(relativeIdpLogoutUri);
        ub.queryParam("wreply", getClientLogoutUri(client, params));
        ub.queryParam(OAuthConstants.CLIENT_ID, client.getClientId());
        return ub.build().normalize();
    }

    public void setRelativeIdpLogoutUri(String relativeIdpLogoutUri) {
        this.relativeIdpLogoutUri = relativeIdpLogoutUri;
    }

}
