package org.apache.cxf.fediz.service.oidc;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.w3c.dom.Element;

public class SAMLClaimsProvider implements ClaimsProvider {

    @Override
    public Map<String, Object> extract(Principal principal) {
        FedizPrincipal fedizPrincipal = (FedizPrincipal) principal;
        Map<String, Object> claims = new HashMap<>();
        Element samlToken = fedizPrincipal.getLoginToken();
        Assertion saml2Assertion = getSaml2Assertion(samlToken);
        if (saml2Assertion != null) {
            // issueInstant
            DateTime issueInstant = saml2Assertion.getIssueInstant();
            if (issueInstant != null) {
                claims.put("iat", issueInstant.toDate());
            }

            // expiryTime
            if (saml2Assertion.getConditions() != null) {
                DateTime expires = saml2Assertion.getConditions().getNotOnOrAfter();
                if (expires != null) {
                    claims.put("exp", expires.toDate());
                }
            }

            // authInstant
            if (!saml2Assertion.getAuthnStatements().isEmpty()) {
                DateTime authInstant =
                        saml2Assertion.getAuthnStatements().get(0).getAuthnInstant();
                claims.put("auth_time", authInstant.toDate());
            }
        }

        // Map claims
        if (fedizPrincipal.getClaims() != null) {
            for (Claim c : fedizPrincipal.getClaims()) {
                if (!(c.getValue() instanceof String)) {
                    continue;
                }
                claims.put(mapClaimName(c.getClaimType().toString()), c.getValue());
            }
        }

        return claims;
    }

    private String mapClaimName(String samlClaimType) {
        return samlClaimType;
    }

    @Override
    public boolean supports(Principal principal) {
        return principal instanceof FedizPrincipal;
    }

    private Assertion getSaml2Assertion(Element samlToken) {
        // Should a null assertion lead to the exception ?
        try {
            SamlAssertionWrapper wrapper = new SamlAssertionWrapper(samlToken);
            return wrapper.getSaml2();
        } catch (WSSecurityException ex) {
            throw new OAuthServiceException("Error converting SAML token", ex);
        }
    }
}
