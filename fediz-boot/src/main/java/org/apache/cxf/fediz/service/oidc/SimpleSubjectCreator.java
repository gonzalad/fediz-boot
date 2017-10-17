package org.apache.cxf.fediz.service.oidc;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;

public class SimpleSubjectCreator implements ClaimsMapper {

    @Override
    public Map<String, Object> extract(Principal principal) {
        Authentication authentication = (Authentication) principal;
        Map<String, Object> claims = new HashMap<>();

        // Map claims
        List<String> roles = authentication.getAuthorities().stream().map(it -> it.getAuthority()).collect(Collectors.toList());
        if (!roles.isEmpty()) {
            claims.put(FedizSubjectCreator.ROLES_CLAIM, roles);
        }
        return claims;
    }

    @Override
    public boolean supports(Principal principal) {
        return principal instanceof Authentication;
    }
}
