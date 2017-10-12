package org.apache.cxf.fediz.service.oidc;

import java.security.Principal;
import java.util.Map;

public interface ClaimsProvider {
    Map<String, Object> extract(Principal principal);

    boolean supports(Principal principal);
}
