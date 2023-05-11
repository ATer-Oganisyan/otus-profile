import java.io.IOException;
import java.io.OutputStream;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.*;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.sql.*;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.URI;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

public class ProfileServer {

    private static HttpClient client = HttpClient.newBuilder().build();
    private static String sessionServiceHost = "";
    private static String userCrudHostServiceHost = "";
    private static String scheme = "http://";

    private static Map<String, Map<String, String>> sessions = new HashMap<>();

    public static void main(String[] args) throws Exception {
        System.out.println("Profile service version: " + args[2]);
        userCrudHostServiceHost = args[1];
        sessionServiceHost = args[0];
        System.out.println("userCrudHostServiceHost: " + userCrudHostServiceHost);
        System.out.println("sessionServiceHost: " + sessionServiceHost);
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/", new MyHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            System.out.println("Request accepted");
            String path = t.getRequestURI().getPath();
            System.out.println("Path: " + path);
            if ("/health".equals(path)) {
                System.out.println("matched health");
                routeHealth(t);
            } else if ("/user/get".equals(path)) {
                System.out.println("matched get");
                routeGetUser(t);
            } else if ("/user/create".equals(path)) {
                System.out.println("matched session");
                routeCreateUser(t);
            } else {
                System.out.println("not matched");
                String response = "{\"status\": \"not found\"}";
                t.sendResponseHeaders(404, response.length());
                OutputStream os = t.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }

    static private void routeHealth(HttpExchange t) throws IOException {
        System.out.println("Request accepted");
        String response = "{\"status\": \"OK\"}";
        t.sendResponseHeaders(200, response.length());
        OutputStream os = t.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    static private String getUserByLogin(String login) {
        String body = "login:" + login;
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(scheme + userCrudHostServiceHost + "/get-by-login"))
                .timeout(Duration.ofMinutes(1))
                .header("Content-Type", "plain/text")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response;
        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException e) {
            System.out.println("IOException");
            throw new RuntimeException();
        } catch (InterruptedException e) {
            System.out.println("IOException");
            throw new RuntimeException();
        }

        if (response.statusCode() != 200) {
            return null;
        }
        return response.body();
    }

    static private HttpResponse<String> getUserById(String id) {
        String body = "id:" + id;
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(scheme + userCrudHostServiceHost + "/get-by-id"))
                .timeout(Duration.ofMinutes(1))
                .header("Content-Type", "plain/text")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response;
        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException e) {
            System.out.println("IOException");
            throw new RuntimeException();
        } catch (InterruptedException e) {
            System.out.println("IOException");
            throw new RuntimeException();
        }

        return response;
    }

    private static String getMd5(String input) {
        try {
            System.out.println("getMd5 input = " + input);
            System.out.println("MessageDigest md = MessageDigest.getInstance");
            MessageDigest md = MessageDigest.getInstance("MD5");
            System.out.println("byte[] messageDigest = md.digest(input.getBytes());");
            byte[] messageDigest = md.digest(input.getBytes());
            System.out.println("messageDigest = " + messageDigest);
            BigInteger no = new BigInteger(1, messageDigest);
            System.out.println("BigInteger no = new BigInteger(1, messageDigest);");
            String hashtext = no.toString(16);
            System.out.println("String hashtext = no.toString(16);");
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            System.out.println("hashtext = " + hashtext);
            return hashtext;
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException");
            return null;
        }
    }

    static private void routeGetUser(HttpExchange t) throws IOException {
        System.out.println("Route getUser");
        Headers headers = t.getRequestHeaders();
        System.out.println("headers = " + headers);
        printLogs(headers.values());
        List<String> headersList;
        if (headers == null) {
            System.out.println("headers = null");
            headersList = new ArrayList<>();
        } else {
            System.out.println("headers.get");
            headersList = headers.get("Cookie");
        }
        String cookieString = String.join(";", headersList);
        System.out.println("cookieString = " + cookieString);
        Map<String, String> cookie = postToMap(new StringBuilder(cookieString));
        System.out.println("cookie = " + cookie);
        String token = cookie.get("token");
        System.out.println("token = " + token);
        String userId = queryToMap(t.getRequestURI().getQuery()).get("id");
        String r;
        String body = "token:" + token;
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(scheme + sessionServiceHost + "/session"))
                .timeout(Duration.ofMinutes(1))
                .header("Content-Type", "plain/text")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response;
        System.out.println("HttpResponse<String> response;");
        try {
            System.out.println("try");
            response = client.send(request, BodyHandlers.ofString());
            System.out.println("response = client.send(request, BodyHandlers.ofString());");
        } catch (IOException e) {
            System.out.println("IOException");
            throw new RuntimeException();
        } catch (InterruptedException e) {
            System.out.println("InterruptedException");
            throw new RuntimeException();
        }

        System.out.println("if (response.statusCode() == 403)");
        if (response.statusCode() == 403) {
            System.out.println("error:403");
            r = "session is not found";
            t.sendResponseHeaders(403, r.length());
            OutputStream os = t.getResponseBody();
            os.write(r.getBytes());
            os.close();
            return;
        }

        System.out.println("Map<String, String> userInfo = postToMap(new StringBuilder(response.body()));");
        Map<String, String> userInfo = postToMap(new StringBuilder(response.body()));
        System.out.println("session server response body: " + response.body());
        System.out.println("userId = " + userId);
        System.out.println("role = " + userInfo.get("role"));
        System.out.println("id = " + userInfo.get("id"));
        System.out.println("id == userId: " + (userId.equals(userInfo.get("id"))));
        System.out.println("role == admin: " + ("admin".equals(userInfo.get("role"))));
        if (!"admin".equals(userInfo.get("role")) && !userId.equals(userInfo.get("id"))) {
            System.out.println("error:403");
            r = "not permitted";
            t.sendResponseHeaders(403, r.length());
            OutputStream os = t.getResponseBody();
            os.write(r.getBytes());
            os.close();
            return;
        }

        System.out.println("if (resp.statusCode() == 200) {");
        HttpResponse<String> resp = getUserById(userId);
        if (resp.statusCode() == 200) {
            r = resp.body();
            t.sendResponseHeaders(200, r.length());
            OutputStream os = t.getResponseBody();
            os.write(r.getBytes());
            os.close();
            return;
        }

        System.out.println("if (resp.statusCode() == 404) {");
        if (resp.statusCode() == 404) {
            r = "user is not found";
            t.sendResponseHeaders(404, r.length());
            OutputStream os = t.getResponseBody();
            os.write(r.getBytes());
            os.close();
            return;
        }

        r = "internal server error";
        t.sendResponseHeaders(500, r.length());
        OutputStream os = t.getResponseBody();
        os.write(r.getBytes());
        os.close();
        return;
    }

    static private void routeCreateUser(HttpExchange t) throws IOException {
        Map<String, String> q = postToMap(buf(t.getRequestBody()));
        String r;
        String name = q.get("name");
        String age = q.get("age");
        String login = q.get("login");
        String pwd = getMd5(q.get("pwd"));
        String body = "name:" + name + "\nage:" + age + "\nlogin:" + login + "\npwd:" + pwd;
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(scheme + userCrudHostServiceHost + "/user/create"))
                .timeout(Duration.ofMinutes(1))
                .header("Content-Type", "plain/text")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response;
        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException e) {
            System.out.println("IOException");
            throw new RuntimeException();
        } catch (InterruptedException e) {
            System.out.println("InterruptedException");
            throw new RuntimeException();
        }

        if (response.statusCode() != 200) {
            System.out.println("error: incorrect answer from crud server");
            r = "internal server error";
            t.sendResponseHeaders(500, r.length());
            OutputStream os = t.getResponseBody();
            os.write(r.getBytes());
            os.close();
            return;
        }

        r = getUserByLogin(login);
        if (r == null) {
            System.out.println("error: incorrect answer from crud server");
            r = "internal server error";
            t.sendResponseHeaders(500, r.length());
            OutputStream os = t.getResponseBody();
            os.write(r.getBytes());
            os.close();
            return;
        }
        t.sendResponseHeaders(200, r.length());
        OutputStream os = t.getResponseBody();
        os.write(r.getBytes());
        os.close();
        return;
    }

    static private Map<String, String> queryToMap(String query) {
        if(query == null) {
            return new HashMap<>();
        }
        Map<String, String> result = new HashMap<>();
        for (String param : query.split("&")) {
            String[] entry = param.split("=");
            if (entry.length > 1) {
                result.put(entry[0], entry[1]);
            }else{
                result.put(entry[0], "");
            }
        }
        return result;
    }

    static private Map<String, String> postToMap(StringBuilder body){
        String[] parts = body
                .toString()
                .replaceAll("\r", "")
                .replaceAll("=", ":")
                .replaceAll(" ", "")
                .replaceAll(";", "\n")
                .replaceAll(",", "\n")
                .replaceAll("{", "")
                .replaceAll("}", "")
                .split("\n");
        Map<String, String> result = new HashMap<>();
        for (String part: parts) {
            String[] keyVal = part.split(":");
            result.put(keyVal[0], keyVal[1]);
        }
        System.out.println("buf: " + result.toString());
        return result;
    }

    static private StringBuilder buf(InputStream inp)  throws UnsupportedEncodingException, IOException {
        InputStreamReader isr =  new InputStreamReader(inp,"utf-8");
        BufferedReader br = new BufferedReader(isr);
        int b;
        StringBuilder buf = new StringBuilder(512);
        while ((b = br.read()) != -1) {
            buf.append((char) b);
        }
        br.close();
        isr.close();
        System.out.println("buf : " + buf);
        return buf;
    }
}