package org.apache.cxf.fediz.service.oidc;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.w3c.dom.Element;

public class SAMLClaimsProvider implements ClaimsMapper {

	private Map<String, String> supportedClaims = Collections.emptyMap();
	
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
                String mappedName = mapClaimName(c.getClaimType().toString());
                if (mappedName != null) {
                    claims.put(mappedName, c.getValue());
                }
            }
        }

        return claims;
    }

    private String mapClaimName(String samlClaimType) {
    	// The typed checks can be dropped if we say all the mappings 
    	// must be set in supportedClaims
    	if (ClaimTypes.FIRSTNAME.equals(samlClaimType)) {
            return IdToken.GIVEN_NAME_CLAIM;
        } else if (ClaimTypes.LASTNAME.equals(samlClaimType)) {
            return IdToken.FAMILY_NAME_CLAIM;
        } else if (ClaimTypes.EMAILADDRESS.equals(samlClaimType)) {
            return IdToken.EMAIL_CLAIM;
        } else {
            return supportedClaims.get(samlClaimType);
        }
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
    
    /**
     * Set a map of supported claims. The map is from a SAML ClaimType URI String to a claim value that is
     * sent in the claims parameter. So for example:
     * http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role -> role
     * If the token contains a the former, and the OpenId claims contains the latter, then the claim value
     * will be encoded in the IdToken using the latter key.
     */
    public void setSupportedClaims(Map<String, String> supportedClaims) {
        this.supportedClaims = supportedClaims;
        //<util:map id="supportedClaims">
        // <!-- we only need the below 3 mappings if we drop the typed checks in mapClaimName(String)
        //  <entry key="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" value="given_name" />
        //  <entry key="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" value="family_name" />
        //  <entry key="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" value="email" />
        // -->
        //  <entry key="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role" value="roles" />
        //</util:map> 
    }
}
