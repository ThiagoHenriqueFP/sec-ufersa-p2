package dataCenter;

import common.*;
import sensors.TypeOfMeasurement;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server implements Runnable {
    private final Integer port;
    private final static Map<String, String> ips = new HashMap<>();
    private final static Set<Integer> edges = new HashSet<>() {{
        add(8080);
    }};

    private final static Map<TypeOfMeasurement, List<Double>> db = new HashMap<>();

    private static PublicKey edgePublicKey;
    private static KeyPair serverKeys;

    static {
        try {
            serverKeys = Crypto.getRsaKeyPar();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public Server(Ports port) {
        this.port = port.getPort();
    }

    public static Integer discover() {
        return edges.stream().findFirst().orElse(Ports.EDGE.getPort());
    }

    private static String getAuth(String addr) {
        if (!ips.containsKey(addr)) {
            String hash = getHash(addr);

            ips.put(addr, hash);
        }

        String edgePublicKeyBase64 = Base64.getEncoder().encodeToString(edgePublicKey.getEncoded());
        String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeys.getPublic().getEncoded());
        System.out.println("[SERVER] sending hashes to client");
        return ips.get(addr) + "<|>" + edgePublicKeyBase64 + "<|>" + serverPublicKeyBase64;
    }

    private static String getHash(String textoOriginal) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] encodedhash = digest.digest(textoOriginal.getBytes(StandardCharsets.UTF_8));

            return bytesToHex(encodedhash);

        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar hash", e);
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static Response register(Object body) {
        System.out.println("[SERVER] registering an edge server");
        edgePublicKey = (PublicKey) body;
        return new Response(serverKeys.getPublic());
    }

    @Override
    public void run() {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("[SERVER] servidor iniciado na porta " + port);
            while (true) {
                Socket clientSocket = serverSocket.accept();

                executor.submit(() -> {
                    try {
                        process(clientSocket);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
            }
        } catch (IOException e) {
            System.out.println("[SERVER] servidor encerrando por falha");
            e.printStackTrace();
        }
    }

    private void process(Socket clientSocket) throws IOException {
        try {
            String ip = clientSocket.getInetAddress().getHostAddress();

            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            out.flush();

            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

            Object preParsed = in.readObject();
            Request request;

            if (preParsed instanceof SecurePacket) {
                byte[] rawBytes = Crypto.applyAuth((SecurePacket) preParsed, serverKeys.getPrivate());

                request = (Request) Utils.deserialize(rawBytes);
            } else {
                request = (Request) preParsed;
            }

            Response response;
            System.out.println("[SERVER] processando " + ip + " requisitando " + request.type());

            switch (request.type()) {
                case DISCOVERY -> response = new Response(discover());
                case ACKNOWLEDGE -> response = new Response(getAuth(ip));
                case REGISTER -> response = register(request.body());
                case SYNC -> response = sync(request.body());
                default -> throw new RuntimeException("Invalid request type");
            }

            out.writeObject(response);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            clientSocket.close();
        }
    }

    private static Response sync(Object body) {
        Map<TypeOfMeasurement, List<Double>> data = (Map<TypeOfMeasurement, List<Double>>) body;

        System.out.println(data);

        data.forEach((k, v) -> {
            var list = db.get(k);
            list.addAll(v);
            db.put(k, list);
        });

        return new Response(null);
    }
}
