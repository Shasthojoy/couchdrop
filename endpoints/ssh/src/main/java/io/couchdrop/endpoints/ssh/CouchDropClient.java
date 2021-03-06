package io.couchdrop.endpoints.ssh;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.io.File;
import java.io.IOException;

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

    public static void upload(String apiEndpoint, String token, File file, String relativePath) {
        try {
            Unirest.post(apiEndpoint + "/push/upload/" + token)
                    .header("accept", "application/json")
                    .field("file", file)
                    .field("path", relativePath)
                    .asJson();
        } catch (UnirestException e) {
            e.printStackTrace();
        }
    }

    public static String download(String apiEndpoint, String token, String relativePath) throws IOException {
        HttpResponse<JsonNode> jsonResponse = null;

        try {
            jsonResponse = Unirest.post(apiEndpoint + "/pull/download/" + token)
                    .header("accept", "application/json")
                    .field("path", relativePath)
                    .asJson();

            if (jsonResponse.getStatus() == 404){
                throw new IOException(jsonResponse.getBody().getObject().getString("error"));
            }

            if (jsonResponse.getStatus() == 403){
                throw new IOException(jsonResponse.getBody().getObject().getString("error"));
            }
        } catch (UnirestException e) {
            throw new IOException("File not found or a system error occurred");
        }
        return jsonResponse.getBody().getObject().getString("b64_content");
    }

    public static String authentication__get_token(String apiEndpoint, String apiToken, String username) {
        HttpResponse<JsonNode> jsonResponse = null;
        try {
            jsonResponse = Unirest.post(apiEndpoint + "/authenticate/get/token")
                    .header("accept", "application/json")
                    .field("username", username)
                    .field("service_token", apiToken)
                    .asJson();
        } catch (UnirestException e) {
            e.printStackTrace();
            return null;
        }

        return jsonResponse.getBody().getObject().getString("token");
    }

    public static String authentication__get_allowed_public_key(String apiEndpoint, String apiToken,String username) {
        HttpResponse<JsonNode> jsonResponse = null;
        try {
            jsonResponse = Unirest.post(apiEndpoint + "/authenticate/get/pub")
                    .header("accept", "application/json")
                    .field("username", username)
                    .field("service_token", apiToken)
                    .asJson();
        } catch (UnirestException e) {
            e.printStackTrace();
            return null;
        }

        return jsonResponse.getBody().getObject().getString("public_key");
    }
}
