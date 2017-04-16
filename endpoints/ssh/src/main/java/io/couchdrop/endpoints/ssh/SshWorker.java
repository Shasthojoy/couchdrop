package io.couchdrop.endpoints.ssh;

import com.sun.xml.internal.ws.util.StreamUtils;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.common.file.nativefs.NativeFileSystemView;
import org.apache.sshd.common.file.nativefs.NativeSshFile;
import org.apache.sshd.common.file.nativefs.NativeSshFileNio;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.*;
import org.apache.sshd.server.auth.CachingPublicKeyAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.ScpCommand;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

import static sun.plugin2.util.SystemUtil.decodeBase64;

public class SshWorker {
    private String tempStoragePath;
    private String apiEndpoint;
    private String apiToken;

    static class ApiAccessToken {
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
            return new BetterNativeFileSystemView(session.getUsername(), roots, "/");
        }
    }

    class BetterNativeSshFileNio extends NativeSshFileNio {

        public BetterNativeSshFileNio(NativeFileSystemView nativeFileSystemView, String fileName, File file, String userName) {
            super(nativeFileSystemView, fileName, file, userName);
        }

        @Override
        public String toString() {
            return super.file.getAbsolutePath();
        }
    }

    class BetterNativeFileSystemView extends NativeFileSystemView {
        public BetterNativeFileSystemView(String userName, Map<String, String> roots, String current) {
            super(userName, roots, current);
        }

        @Override
        public NativeSshFile createNativeSshFile(String name, File file, String userName) {
            name = deNormalizeSeparateChar(name);
            return new BetterNativeSshFileNio(this, name, file, userName);
        }
    }


    public static final Session.AttributeKey<ApiAccessToken> ATTRIBUTE__GRANTED_TOKEN = new Session.AttributeKey<ApiAccessToken>() {
        @Override
        public String toString() {
            return "ATTRIBUTE__GRANTED_TOKEN";
        }
    };

    class ScpCommandExtension extends ScpCommand {

        public ScpCommandExtension(String command) {
            super(command);
        }

        public String getPath(){
            return path;
        }

        public ExitCallback getExitCallback() {
            return this.callback;
        }

        public void run() {
            int exitValue = ScpHelper.OK;
            String exitMessage = null;
            ScpHelper helper = new ScpHelper(in, out, root);
            try {
                if (optT) {
                    if(path.equals(".") || !path.contains("/")){
                        helper.receive(root.getFile(path), optR, optD, optP);

                    }else{
                        SshFile directory = root.getFile(path);
                        String fullDirectoryPath = directory.toString();
                        File targetDirectory = new File(fullDirectoryPath);
                        targetDirectory.mkdirs();
                        helper.receive(directory, optR, optD, optP);
                    }

                } else if (optF) {
                    helper.send(Collections.singletonList(path), optR, optP);
                } else {
                    throw new IOException("Unsupported mode");
                }
            } catch (IOException e) {
                try {
                    exitValue = ScpHelper.ERROR;
                    exitMessage = e.getMessage() == null ? "" : e.getMessage();
                    out.write(exitValue);
                    out.write(exitMessage.getBytes());
                    out.write('\n');
                    out.flush();
                } catch (IOException e2) {
                    // Ignore
                }
                log.info("Error in scp command", e);
            } finally {
                if (callback != null) {
                    callback.onExit(exitValue, exitMessage);
                }
            }
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

            private boolean findFiles(String rootPath, List<File> ret) {
                File current = new File(rootPath);
                for (File file : current.listFiles()){
                    if (file.isDirectory()){
                        findFiles(file.getPath(), ret);
                    }else{
                        ret.add(file);
                    }
                }

                return false;
            }

            private void upload_file() {
                System.out.println(scp_command.getPath());

                /* Pull the token from our environment and create a path */
                String auth_token = env.getEnv().get(ATTRIBUTE__GRANTED_TOKEN.toString());
                String path = String.format("%s/%s", tempStoragePath, auth_token);

                /* Upload the files*/
                List<File> filesToUpload = new LinkedList<>();
                findFiles(path, filesToUpload);

                for (File file : filesToUpload) {
                    String relativePath = file.getPath().replace(path, "");
                    CouchDropClient.upload(apiEndpoint, auth_token, file, relativePath);
                    file.delete();
                }
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


    public SshServer createSshServer(int port, String hostKeyPath, String tempStoragePath, String apiEndpoint, String apiToken) {
        this.tempStoragePath = tempStoragePath;
        this.apiEndpoint = apiEndpoint;
        this.apiToken = apiToken;

        SshServer server = SshServer.setUpDefaultServer();
        server.setHost("0.0.0.0");
        server.setPort(port);
        server.setFileSystemFactory(new TmpFileSystemFactory());
        server.setChannelFactories(Arrays.<NamedFactory<Channel>>asList(
                new ChannelSessionDecoratorFactory()
        ));
        server.setCommandFactory(new ScpCommandFactoryDecorator());
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(hostKeyPath, "RSA"));

        server.setPublickeyAuthenticator(new CouchDropPublicKeyAuthenticator(this.apiEndpoint, this.apiToken));
        server.setPasswordAuthenticator(new CouchDropPasswordAuthenticator(this.apiEndpoint, this.apiToken));
        return server;
    }


}