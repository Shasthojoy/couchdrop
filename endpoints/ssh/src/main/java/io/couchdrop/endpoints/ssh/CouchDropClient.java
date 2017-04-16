package io.couchdrop.endpoints.ssh;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.io.File;

/**
 * Created by michaellawson on 18/06/16.
 */

public class CouchDropClient {

    public static String authenticate(String apiEndpoint, String username, String password) {
        HttpResponse<JsonNode> jsonResponse = null;
        try {
            jsonResponse = Unirest.post(apiEndpoint + "/authenticate")
                    .header("accept", "application/json")
                    .field("username", username)
                    .field("password", password)
                    .asJson();
        } catch (UnirestException e) {
            e.printStackTrace();
            return null;
        }

        return jsonResponse.getBody().getObject().getString("token");
    }

    public static void upload(String apiEndpoint, String token, File file) {
        try {
            Unirest.post(apiEndpoint + "/push/upload/" + token)
                    .header("accept", "application/json")
                    .field("file", file)
                    .field("path", file.getAbsolutePath())
                    .asJson();
        } catch (UnirestException e) {
            e.printStackTrace();
        }
    }
}
