package io.couchdrop.endpoints.ssh;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.nativefs.NativeFileSystemView;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.ScpCommand;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;

import java.io.*;
import java.util.*;

public class SshWorker implements PasswordAuthenticator {
    private String tempStoragePath;
    private String apiEndpoint;

    class ApiAccessToken {
        public String token;

        public ApiAccessToken(String granted_token) {
            this.token = granted_token;
        }
    }

    class TmpFileSystemFactory implements FileSystemFactory {

        public FileSystemView createFileSystemView(Session session) {
            String dir = tempStoragePath + "/" + session.getAttribute(ATTRIBUTE__GRANTED_TOKEN).token;
            new File(dir).mkdir();
            Map<String, String> roots = new HashMap<String, String>();
            roots.put("/", dir);
            return new NativeFileSystemView(session.getUsername(), roots, "/");
        }
    }

    private static final Session.AttributeKey<ApiAccessToken> ATTRIBUTE__GRANTED_TOKEN = new Session.AttributeKey<ApiAccessToken>() {
        @Override
        public String toString() {
            return "ATTRIBUTE__GRANTED_TOKEN";
        }
    };

    class ScpCommandExtension extends ScpCommand {

        public ScpCommandExtension(String command) {
            super(command);
        }

        public ExitCallback getExitCallback() {
            return this.callback;
        }
    }

    class ScpCommandDecorator implements Command, Runnable, FileSystemAware {
        private ScpCommandExtension inner_command;

        class PushFileUpExitCallback implements ExitCallback {

            private ExitCallback real_callback;
            ScpCommandExtension scp_command;
            Environment env;

            public PushFileUpExitCallback(Environment env, ScpCommandExtension scp_command, ExitCallback exitCallback) {
                this.env = env;
                this.scp_command = scp_command;
                this.real_callback = exitCallback;
            }

            private void upload_file() {
                /* Pull the token from our environment and create a path */
                String auth_token = env.getEnv().get(ATTRIBUTE__GRANTED_TOKEN.toString());
                String path = String.format("/%s/%s", tempStoragePath, auth_token);

                /* Upload the files*/
                File couchdrop_api_token = new File(path);
                File[] files = couchdrop_api_token.listFiles();
                assert files != null;
                for (File file : files) {
                    CouchDropClient.upload(apiEndpoint, auth_token, file);
                }

                /* Now that we are done writing the file, we can delete the entire directory */
                for(File file : couchdrop_api_token.listFiles()){
                    file.delete();
                }

                couchdrop_api_token.delete();
            }

            public void onExit(int exitValue) {
                upload_file();
                real_callback.onExit(exitValue);

            }

            public void onExit(int exitValue, String exitMessage) {
                upload_file();
                real_callback.onExit(exitValue, exitMessage);
            }
        }

        public ScpCommandDecorator(String command) {
            this.inner_command = new ScpCommandExtension(command);
        }

        public void run() {
            this.inner_command.run();
        }

        public void setFileSystemView(FileSystemView view) {
            this.inner_command.setFileSystemView(view);
        }

        public void setInputStream(InputStream in) {
            this.inner_command.setInputStream(in);
        }

        public void setOutputStream(OutputStream out) {
            this.inner_command.setOutputStream(out);
        }

        public void setErrorStream(OutputStream err) {
            this.inner_command.setErrorStream(err);
        }

        public void setExitCallback(ExitCallback callback) {
            this.inner_command.setExitCallback(callback);
        }

        public void start(Environment env) throws IOException {
            this.setExitCallback(new PushFileUpExitCallback(env, inner_command, this.inner_command.getExitCallback()));
            this.inner_command.start(env);
        }

        public void destroy() {
            this.inner_command.destroy();
        }
    }

    class ScpCommandFactoryDecorator extends ScpCommandFactory {
        public Command createCommand(String command) {
            if (!command.startsWith("scp")) {
                throw new IllegalArgumentException("Unknown command, does not begin with 'scp'");
            }
            return new ScpCommandDecorator(command);
        }
    }

    class ChannelSessionDecorator extends ChannelSession {
        @Override
        protected boolean handleExec(Buffer buffer) throws IOException {
            // here we can move attributes from the server session to the env
            this.env.set(ATTRIBUTE__GRANTED_TOKEN.toString(), this.session.getAttribute(ATTRIBUTE__GRANTED_TOKEN).token);
            return super.handleExec(buffer);
        }
    }

    class ChannelSessionDecoratorFactory implements NamedFactory<Channel> {
        public String getName() {
            return "session";
        }

        public Channel create() {
            return new ChannelSessionDecorator();
        }
    }

    public SshServer createSshServer(int port, String hostKeyPath, String tempStoragePath, String apiEndpoint) {
        this.tempStoragePath = tempStoragePath;
        this.apiEndpoint = apiEndpoint;

        SshServer server = SshServer.setUpDefaultServer();
        server.setHost("0.0.0.0");
        server.setPort(port);
        server.setFileSystemFactory(new TmpFileSystemFactory());
        server.setChannelFactories(Arrays.<NamedFactory<Channel>>asList(
                new ChannelSessionDecoratorFactory()
        ));
        server.setCommandFactory(new ScpCommandFactoryDecorator());
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(hostKeyPath));
        server.setPasswordAuthenticator(this);
        return server;
    }


    public boolean authenticate(String username, String password, ServerSession session) {
        // We can set attributes here
        String authenticate = CouchDropClient.authenticate(apiEndpoint, username, password);
        if (authenticate != null) {
            session.setAttribute(
                    ATTRIBUTE__GRANTED_TOKEN,
                    new ApiAccessToken(authenticate)
            );
            return true;
        }
        return false;
    }
}