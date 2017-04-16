package io.couchdrop.endpoints.ssh;

import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import static io.couchdrop.endpoints.ssh.SshWorker.ATTRIBUTE__GRANTED_TOKEN;

/**
 * Created by michaellawson on 16/04/17.
 */
public class CouchDropPublicKeyAuthenticator implements PublickeyAuthenticator {
    private final String apiEndpoint;
    private String apiToken;

    public CouchDropPublicKeyAuthenticator(String apiEndpoint, String apiToken) {
        this.apiEndpoint = apiEndpoint;
        this.apiToken = apiToken;
    }

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        // We can set attributes here
        String allowedKey = CouchDropClient.authentication__get_allowed_public_key(this.apiEndpoint, this.apiToken, username);
        if (allowedKey == null) {
            return false;
        }

        byte[] decodeBuffer = Base64.decode(allowedKey);
        ByteBuffer bb = ByteBuffer.wrap(decodeBuffer);
        int len = bb.getInt();
        byte[] type = new byte[len];
        bb.get(type);
        if ("ssh-rsa".equals(new String(type))) {
            BigInteger e = decodeBigInt(bb);
            BigInteger m = decodeBigInt(bb);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(m, e);
            try {
                if (KeyFactory.getInstance("RSA").generatePublic(spec).equals(key)) {
                    String token = CouchDropClient.authentication__get_token(this.apiEndpoint, this.apiToken, username);
                    if (token != null) {
                        session.setAttribute(
                                ATTRIBUTE__GRANTED_TOKEN,
                                new SshWorker.ApiAccessToken(token)
                        );
                        return true;
                    }
                }
            } catch (InvalidKeySpecException e1) {
            } catch (NoSuchAlgorithmException e1) {
            }
        }

        return false;

    }

    private BigInteger decodeBigInt(ByteBuffer bb) {
        int len = bb.getInt();
        byte[] bytes = new byte[len];
        bb.get(bytes);
        return new BigInteger(bytes);
    }
}
