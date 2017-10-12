package org.gonzalad.cxf.fediz.sts.spring;

import javax.security.auth.Subject;

import org.apache.commons.codec.binary.Base64;
import org.apache.cxf.common.security.SimpleGroup;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.WSUsernameTokenPrincipalImpl;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * WSS4J adapter delegating authentication to Spring Security Provider.
 *
 * @author agonzalez
 */
public class SpringSecurityValidatorAdapter implements Validator {

    private static final Logger LOG = LoggerFactory.getLogger(SpringSecurityValidatorAdapter.class);

    static {
        WSSConfig.init();
    }

    private AuthenticationManager authenticationProvider;

    private ExceptionHandler exceptionHandler = new BasicExceptionHandler();

    public SpringSecurityValidatorAdapter(AuthenticationManager authenticationProvider) {
        if (authenticationProvider == null) {
            throw new IllegalArgumentException("authenticationProvider parameter is required");
        }
        this.authenticationProvider = authenticationProvider;
    }

    public void setExceptionHandler(ExceptionHandler exceptionHandler) {
        if (exceptionHandler == null) {
            throw new IllegalArgumentException("exceptionHandler parameter is required");
        }
        this.exceptionHandler = exceptionHandler;
    }

    @Override
    public Credential validate(Credential credential, RequestData requestData) throws WSSecurityException {
        Authentication authentication = convert(credential, requestData);
        Authentication authenticated = null;
        try {
            authenticated = authenticationProvider.authenticate(authentication);
        } catch (AuthenticationException e) {
            handleException(e);
        }
        addToCredential(authenticated, credential);
        return credential;
    }

    protected Authentication convert(Credential credential, RequestData requestData) {
        UsernameToken usernameToken = credential.getUsernametoken();
        String pwType = usernameToken.getPasswordType();
        LOG.debug("UsernameToken user {}", usernameToken.getName());
        LOG.debug("UsernameToken password type {}", pwType);

        if (!WSConstants.PASSWORD_TEXT.equals(pwType)) {
            LOG.debug("Authentication failed - pwdType not accepted: digest passwords are not accepted");
            throw new AuthenticationServiceException("Authentication failed - pwdType not accepted");
        }
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(usernameToken.getName(), usernameToken.getPassword());
        authentication.setDetails(requestData);
        return authentication;
    }

    protected void handleException(AuthenticationException exception) throws WSSecurityException {
        exceptionHandler.handleException(exception);
    }

    protected void addToCredential(Authentication authentication, Credential credential) {
        if (authentication == null) {
            throw new IllegalArgumentException("authentication parameter is required");
        }
        Subject subject = new Subject();
        WSUsernameTokenPrincipalImpl principal = new WSUsernameTokenPrincipalImpl(authentication.getName(), false);
        UsernameToken usernameToken = credential.getUsernametoken();
        principal.setPassword(usernameToken.getPassword());
        principal.setNonce(Base64.decodeBase64(usernameToken.getNonce()));
        credential.setPrincipal(principal);
        subject.getPrincipals().add(principal);
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            subject.getPrincipals().add(new SimpleGroup(authority.getAuthority(), authentication.getName()));
        }
        subject.setReadOnly();
        credential.setSubject(subject);
    }

    /**
     * Converts a Spring Security exception to a WSSecurityException one
     *
     * @author agonzalez
     */
    public interface ExceptionHandler {

        void handleException(AuthenticationException exception) throws WSSecurityException;
    }

    /**
     * Basic exception handler.
     *
     * Differentiates between internal authentication service exceptions (in this case, we return wsErrorCode=FAILURE)
     * and functional authentication error (i.e. badCredentials, accountLocked, etc..., in this case we return
     * wsCode=FAILED_AUTHENTICATION)
     */
    public static class BasicExceptionHandler implements SpringSecurityValidatorAdapter.ExceptionHandler {

        public void handleException(AuthenticationException exception) throws WSSecurityException {
            //@formatter:off
            if (exception instanceof BadCredentialsException
                    || exception instanceof UsernameNotFoundException
                    || exception instanceof AuthenticationCredentialsNotFoundException
                    || exception instanceof AccountStatusException) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, exception);
            }
            //@formatter:on
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, exception);
        }
    }

}
