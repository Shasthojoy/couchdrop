package io.couchdrop.endpoints.ssh;

import org.apache.sshd.SshServer;

/**
 * Created by michaellawson on 18/06/16.
 */
public class SshEndpoint {

    public static void main(String[] args) throws Exception {
        String RSA_KEY = System.getenv("COUCHDROP_SSH_");
        String TMP_DIR = System.getenv("COUCHDROP_SSH__TMP_DIR");
        String API_ENDPOINT = System.getenv("COUCHDROP_SSH__API_ENDPOINT");

        io.couchdrop.endpoints.ssh.SshWorker server = new io.couchdrop.endpoints.ssh.SshWorker();
        SshServer sshServer = server.createSshServer(5022, RSA_KEY, TMP_DIR, API_ENDPOINT);
        sshServer.start();

        while (true) {
            Thread.sleep(4000);
        }
    }
}
