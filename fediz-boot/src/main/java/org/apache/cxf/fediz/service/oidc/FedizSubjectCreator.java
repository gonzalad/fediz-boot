/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.fediz.service.oidc;

import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;

import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FedizConstants;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.provider.SubjectCreator;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.idp.OidcUserSubject;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;


public class FedizSubjectCreator implements SubjectCreator {
    public static final String ROLES_CLAIMS = "roles";
    private static final String ROLES_SCOPE = "roles";
    private boolean stripPathFromIssuerUri;
    private String issuer;
    private long defaultTimeToLive = 3600L;
    private Map<String, String> supportedClaims = Collections.emptyMap();

    /**
     * TODO add SimpleClaimsMapper
     */
    private List<ClaimsMapper> claimsProviders = Arrays.asList(new SAMLClaimsProvider(), new SimpleSubjectCreator());

    @Override
    public OidcUserSubject createUserSubject(MessageContext mc,
                                             MultivaluedMap<String, String> params) throws OAuthServiceException {
        Principal principal = mc.getSecurityContext().getUserPrincipal();
        ClaimsMapper claimsProvider = retrieveClaimsProvider(principal, mc.getHttpServletRequest());

        // In the future FedizPrincipal will likely have JWT claims already prepared,
        // with IdToken being initialized here from those claims
        OidcUserSubject oidcSub = new OidcUserSubject();
        oidcSub.setLogin(principal.getName());

        oidcSub.setId(principal.getName());

        IdToken idToken = convertToIdToken(mc,
                oidcSub.getLogin(),
                oidcSub.getId(),
                claimsProvider.extract(principal),
                params);
        oidcSub.setIdToken(idToken);
        oidcSub.setRoles(idToken.getListStringProperty(ROLES_SCOPE));
        // UserInfo can be populated and set on OidcUserSubject too.
        // UserInfoService will create it otherwise.

        return oidcSub;
    }

    private ClaimsMapper retrieveClaimsProvider(Principal principal, HttpServletRequest request) {

        // in case a custom authenticationProvider adds its own claimsProvider
        // i.e. custom authenticationProvider handles both authentication and claimsProvider
        ClaimsMapper claimsProvider = (ClaimsMapper) request.getAttribute("claimsProvider");
        if (claimsProvider != null) {
            return claimsProvider;
        }

        for (ClaimsMapper provider : claimsProviders) {
            if (provider.supports(principal)) {
                return provider;
            }
        }
        throw new OAuthServiceException("No claimsProvider for current principal");
    }

    private IdToken convertToIdToken(MessageContext mc,
                                     String subjectName,
                                     String subjectId,
                                     Map<String, Object> claims,
                                     MultivaluedMap<String, String> params) {
        // The current SAML Assertion represents an authentication record.
        // It has to be translated into IdToken (JWT) so that it can be returned
        // to client applications participating in various OIDC flows.

        IdToken idToken = new IdToken();

        //TODO: make the mapping between the subject name and IdToken claim configurable
        idToken.setPreferredUserName(subjectName);
        idToken.setSubject(subjectId);

        // issueInstant
        // TODO replace those with constants
        Date iat = (Date) claims.get("iat");
        idToken.setIssuedAt(iat != null ? iat.getTime() / 1000 : System.currentTimeMillis() / 1000);

        // expiryTime
        Date exp = (Date) claims.get("exp");
        idToken.setIssuedAt(exp != null ? exp.getTime() / 1000 : System.currentTimeMillis() / 1000);

        // authInstant
        Date auth_time = (Date) claims.get("auth_time");
        idToken.setAuthenticationTime(auth_time != null ? auth_time.getTime() / 1000 : System.currentTimeMillis() / 1000);

        // issuer
        String realIssuer = null;
        if (issuer == null || issuer.startsWith("/")) {
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
            // custom scopes to claims mapping
            requestedClaimsList.addAll(getCustomScopeClaims(scopes));
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
            for (Map.Entry<String, Object> c : claims.entrySet()) {
                if (!(c.getValue() instanceof String)) {
                    continue;
                }
                // TODO : change SAML names to oidc names
                if (ClaimTypes.FIRSTNAME.equals(c.getKey())) {
                    idToken.setGivenName((String) c.getValue());
                    firstName = (String) c.getValue();
                } else if (ClaimTypes.LASTNAME.equals(c.getKey())) {
                    idToken.setFamilyName((String) c.getValue());
                    lastName = (String) c.getValue();
                } else if (ClaimTypes.EMAILADDRESS.equals(c.getKey())) {
                    idToken.setEmail((String) c.getValue());
                } else if (supportedClaims.containsKey(c.getKey().toString())
                        && requestedClaimsList.contains(supportedClaims.get(c.getKey().toString()))) {
                    idToken.setClaim(supportedClaims.get(c.getKey().toString()), c.getValue());
                }
            }
            if (firstName != null && lastName != null) {
                idToken.setName(firstName + " " + lastName);
            }
        }

        List<Object> roles = (List<Object>) claims.get(ROLES_CLAIMS);
        if (roles != null && !roles.isEmpty()
                && supportedClaims.containsKey(FedizConstants.DEFAULT_ROLE_URI.toString())) {

            String roleClaimName = supportedClaims.get(FedizConstants.DEFAULT_ROLE_URI.toString());
            if (requestedClaimsList.contains(roleClaimName)) {
                idToken.setClaim(roleClaimName, roles);
            }
        }

        return idToken;
    }


    private List<String> getCustomScopeClaims(String[] scopes) {
        // For now the only custom scope (to claims) mapping Fediz supports is
        // roles where the scope name is expected to be 'roles' and the role name must be configured
        String roleClaimName = supportedClaims.get(FedizConstants.DEFAULT_ROLE_URI.toString());
        if (roleClaimName != null && Arrays.asList(scopes).contains(ROLES_SCOPE)) {
            return Collections.singletonList(roleClaimName);
        } else {
            return Collections.emptyList();
        }

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

    public void setClaimsProvider(ClaimsMapper claimsProvider) {
        setClaimsProviders(Collections.singletonList(claimsProvider));
    }

    public void setClaimsProviders(List<ClaimsMapper> claimsProvider) {
        this.claimsProviders = claimsProvider;
    }
}
