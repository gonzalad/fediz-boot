package org.apache.cxf.fediz.service.oidc;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.grants.code.DefaultEHCacheCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

/**
 * TODO: create a fediz-oidc jar module in fediz and move all reusable classes
 * from fediz-oidc:war to fediz-oidc:jar.
 * This way we'll be able to reference those classes and we won't have to copy this class.
 */
public class OAuthDataProviderImpl extends DefaultEHCacheCodeDataProvider {
    private static final Set<String> NON_REDIRECTION_FLOWS =
            new HashSet<String>(Arrays.asList(OAuthConstants.CLIENT_CREDENTIALS_GRANT,
                    OAuthConstants.RESOURCE_OWNER_GRANT));

    @Override
    protected void checkRequestedScopes(Client client, List<String> requestedScopes) {
        String grantType = super.getCurrentRequestedGrantType();
        if (grantType != null && !NON_REDIRECTION_FLOWS.contains(grantType)
                && !requestedScopes.contains(OidcUtils.OPENID_SCOPE)) {
            throw new OAuthServiceException("Required scopes are missing");
        }
    }
}
