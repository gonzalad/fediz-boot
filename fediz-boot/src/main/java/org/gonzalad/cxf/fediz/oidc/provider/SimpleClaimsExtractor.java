package org.gonzalad.cxf.fediz.oidc.provider;

import java.util.Collections;
import java.util.Map;

import org.springframework.security.core.Authentication;

/**
 * TODO map all emails, etc...
 * do we need this interface of do we implement a custom extensible mapping
 * in SubjectCreator ?
 *
 * map preferred username
 *
 * and make it configurable
 */
public class SimpleClaimsExtractor implements ClaimsExtractor {

    @Override
    public Map<String, Object> extract(Authentication authentication) {
        return Collections.emptyMap();
    }
}
