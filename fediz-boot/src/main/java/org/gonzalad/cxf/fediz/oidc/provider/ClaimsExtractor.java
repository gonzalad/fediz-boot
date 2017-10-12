package org.gonzalad.cxf.fediz.oidc.provider;

import java.util.Map;

import org.springframework.security.core.Authentication;

public interface ClaimsExtractor {
    Map<String, Object> extract(Authentication authentication);
}
