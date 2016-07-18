package io.couchdrop.endpoints.ssh;

import org.apache.sshd.SshServer;

/**
 * Created by michaellawson on 18/06/16.
 */
public class SshEndpoint {

    public static void main(String[] args) throws Exception {
        io.couchdrop.endpoints.ssh.SshWorker serverb = new io.couchdrop.endpoints.ssh.SshWorker();
        SshServer sshServer = serverb.createSshServer(5022, "/server/keys/keys.ser", "/server/tmp", "https://api.couchdrop.io");
        sshServer.start();

        while (true) {
            Thread.sleep(4000);
        }
    }
}
