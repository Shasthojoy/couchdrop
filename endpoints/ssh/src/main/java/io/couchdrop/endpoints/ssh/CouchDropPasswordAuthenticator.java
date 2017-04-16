package io.couchdrop.endpoints.ssh;

import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;

import static io.couchdrop.endpoints.ssh.SshWorker.ATTRIBUTE__GRANTED_TOKEN;

/**
 * Created by michaellawson on 16/04/17.
 */
public class CouchDropPasswordAuthenticator implements PasswordAuthenticator {
    private final String apiEndpoint;

    public CouchDropPasswordAuthenticator(String apiEndpoint) {
        this.apiEndpoint = apiEndpoint;
    }

    @Override
    public boolean authenticate(String username, String password, ServerSession session) {
        // We can set attributes here
        String authenticate = CouchDropClient.authenticate(apiEndpoint, username, password);
        if (authenticate != null) {
            session.setAttribute(
                    ATTRIBUTE__GRANTED_TOKEN,
                    new SshWorker.ApiAccessToken(authenticate)
            );
            return true;
        }
        return false;
    }
}
