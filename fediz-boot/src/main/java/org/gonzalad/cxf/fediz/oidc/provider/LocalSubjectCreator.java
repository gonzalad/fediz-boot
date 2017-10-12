package org.gonzalad.cxf.fediz.oidc.provider;

import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FedizConstants;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.provider.SubjectCreator;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.idp.OidcUserSubject;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;
import org.springframework.security.core.Authentication;

/**
 * TODO:
 * - create an interface to map spring security authentication to claims.
 * - create common class/utility between LocalSubjectCreator and FedizSubjectCreator
 * - rename this class (this is a Spring Security subject creator).
 */
public class LocalSubjectCreator implements SubjectCreator {

    private static final String ROLES_SCOPE = "roles";
    private boolean stripPathFromIssuerUri;
    private String issuer;
    private long defaultTimeToLive = 3600L;
    private Map<String, String> supportedClaims = Collections.emptyMap();

    private ClaimsExtractor claimsExtractor = new SimpleClaimsExtractor();

    @Override
    public UserSubject createUserSubject(MessageContext mc,
                                         MultivaluedMap<String, String> params) throws OAuthServiceException {
        Principal principal = mc.getSecurityContext().getUserPrincipal();
        if (!(principal instanceof Authentication)) {
            throw new OAuthServiceException("Unsupported Principal");
        }

        Authentication authentication = (Authentication) principal;
        // In the future FedizPrincipal will likely have JWT claims already prepared,
        // with IdToken being initialized here from those claims
        OidcUserSubject oidcSub = new OidcUserSubject();
        oidcSub.setLogin(principal.getName());
        oidcSub.setId(principal.getName());
        List<String> roles = authentication.getAuthorities().stream().map(it -> it.getAuthority()).collect(Collectors.toList());
        IdToken idToken = convertToIdToken(mc,
                oidcSub.getLogin(),
                oidcSub.getId(),
                new ClaimCollection(),
                roles,
                params);
        oidcSub.setIdToken(idToken);
        oidcSub.setRoles(roles);
        // UserInfo can be populated and set on OidcUserSubject too.
        // UserInfoService will create it otherwise.

        return oidcSub;
    }


    private IdToken convertToIdToken(MessageContext mc,
                                     String subjectName,
                                     String subjectId,
                                     ClaimCollection claims,
                                     List<String> roles,
                                     MultivaluedMap<String, String> params) {
        // The current SAML Assertion represents an authentication record.
        // It has to be translated into IdToken (JWT) so that it can be returned
        // to client applications participating in various OIDC flows.

        IdToken idToken = new IdToken();

        //TODO: make the mapping between the subject name and IdToken claim configurable
        idToken.setPreferredUserName(subjectName);
        idToken.setSubject(subjectId);

        // Check if default issuer, issuedAt and expiryTime values have to be set
        if (issuer != null) {
            String realIssuer = null;
            if (issuer.startsWith("/")) {
                UriBuilder ub = mc.getUriInfo().getBaseUriBuilder();
                URI uri = ub.path(issuer).build();
                if (this.stripPathFromIssuerUri) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(uri.getScheme()).append("://").append(uri.getHost());
                    if (uri.getPort() != -1) {
                        sb.append(':').append(uri.getPort());
                    }
                    realIssuer = sb.toString();
                } else {
                    realIssuer = uri.toString();
                }
            } else {
                realIssuer = issuer;
            }
            idToken.setIssuer(realIssuer);
        }

        long currentTimeInSecs = System.currentTimeMillis() / 1000;
        if (idToken.getIssuedAt() == null) {
            idToken.setIssuedAt(currentTimeInSecs);
        }
        if (idToken.getExpiryTime() == null) {
            idToken.setExpiryTime(currentTimeInSecs + defaultTimeToLive);
        }

        List<String> requestedClaimsList = new ArrayList<String>();
        //Derive claims from scope
        String requestedScope = params.getFirst(OAuthConstants.SCOPE);
        if (requestedScope != null && !requestedScope.isEmpty()) {
            String[] scopes = requestedScope.split(" ");
            //TODO: Note that if the consent screen enabled then it is feasible
            // that the claims added in this code after mapping the scopes to claims
            // may need to be removed if the user disapproves the related scope

            // standard scope to claims mapping:
            requestedClaimsList.addAll(OidcUtils.getScopeClaims(scopes));
        }
        // Additional claims requested
        String requestedClaims = params.getFirst("claims");
        if (requestedClaims != null && !requestedClaims.isEmpty()) {
            requestedClaimsList.addAll(Arrays.asList(requestedClaims.trim().split(" ")));
        }

        // Map claims
        if (claims != null) {
            String firstName = null;
            String lastName = null;
            for (Claim c : claims) {
                if (!(c.getValue() instanceof String)) {
                    continue;
                }
                if (ClaimTypes.FIRSTNAME.equals(c.getClaimType())) {
                    idToken.setGivenName((String) c.getValue());
                    firstName = (String) c.getValue();
                } else if (ClaimTypes.LASTNAME.equals(c.getClaimType())) {
                    idToken.setFamilyName((String) c.getValue());
                    lastName = (String) c.getValue();
                } else if (ClaimTypes.EMAILADDRESS.equals(c.getClaimType())) {
                    idToken.setEmail((String) c.getValue());
                } else if (supportedClaims.containsKey(c.getClaimType().toString())
                        && requestedClaimsList.contains(supportedClaims.get(c.getClaimType().toString()))) {
                    idToken.setClaim(supportedClaims.get(c.getClaimType().toString()), (String) c.getValue());
                }

            }
            if (firstName != null && lastName != null) {
                idToken.setName(firstName + " " + lastName);
            }
        }

        if (roles != null && !roles.isEmpty()
                && supportedClaims.containsKey(FedizConstants.DEFAULT_ROLE_URI.toString())) {

            String roleClaimName = supportedClaims.get(FedizConstants.DEFAULT_ROLE_URI.toString());
            if (requestedClaimsList.contains(roleClaimName)) {
                idToken.setClaim(roleClaimName, roles);
            }
        }

        return idToken;
    }

    public void setIdTokenIssuer(String idTokenIssuer) {
        this.issuer = idTokenIssuer;
    }


    public void setIdTokenTimeToLive(long idTokenTimeToLive) {
        this.defaultTimeToLive = idTokenTimeToLive;
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
    }

    public void setStripPathFromIssuerUri(boolean stripPathFromIssuerUri) {
        this.stripPathFromIssuerUri = stripPathFromIssuerUri;
    }

    public void setClaimsExtractor(ClaimsExtractor claimsExtractor) {
        this.claimsExtractor = claimsExtractor;
    }
}
