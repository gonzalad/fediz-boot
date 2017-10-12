package org.gonzalad.cxf.fediz.sts.callback;

import java.io.IOException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;

/**
 * Used for storing key password in a Spring bean (while obfuscating it).
 */
public class SimpleKeystoreCallbackHandler implements CallbackHandler {

    private String keyPassword;

    public SimpleKeystoreCallbackHandler(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                pc.setPassword(keyPassword);
            }
        }
    }
}
