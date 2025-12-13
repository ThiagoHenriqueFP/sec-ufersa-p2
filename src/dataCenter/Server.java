package dataCenter;

import client.TcpClient;
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
    private final Map<String, String> ips = new HashMap<>();
    private final Set<Integer> edges = new HashSet<>() {{
        add(8080);
    }};

    private final Map<TypeOfMeasurement, List<Double>> db = new HashMap<>();

    private PublicKey proxyPublicKey;
    private PublicKey aclPublicKey;
    private PublicKey edgePublicKey;
    private KeyPair serverKeys;


    private Response requestToACL(Request request) {
        TcpClient client;

        if (aclPublicKey == null) {
            client = new TcpClient(request, Ports.ACL);
        } else {
            client = new TcpClient(request, aclPublicKey, Ports.ACL);
        }

        client.run();

        return client.getResponse();
    }

    private Response requestToProxy(Request request) {
        TcpClient client;

        if (proxyPublicKey == null) {
            client = new TcpClient(request, Ports.PROXY_TCP);
        } else {
            client = new TcpClient(request, proxyPublicKey, Ports.PROXY_TCP);
        }

        client.run();

        return client.getResponse();
    }

    public Server() {
        try {
            serverKeys = Crypto.getRsaKeyPar();

            this.aclPublicKey = (PublicKey) requestToACL(new Request(serverKeys.getPublic(), TypeOfRequest.REGISTER, Ports.SERVER.getPort())).body();
            this.proxyPublicKey = (PublicKey) requestToProxy(new Request(serverKeys.getPublic(), TypeOfRequest.REGISTER, Ports.SERVER.getPort())).body();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public Integer discover() {
        return Ports.PROXY_UDP.getPort();
    }

    private String getAuth(String clientPort) {
        if (!ips.containsKey(clientPort)) {
            String hash = getHash(clientPort);

            ips.put(clientPort, hash);
        }

        String edgePublicKeyBase64 = Base64.getEncoder().encodeToString(proxyPublicKey.getEncoded());
        String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeys.getPublic().getEncoded());
        System.out.println("[SERVER] sending hashes to client");
        return ips.get(clientPort) + "<|>" + edgePublicKeyBase64 + "<|>" + serverPublicKeyBase64;
    }

    private String getHash(String textoOriginal) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] encodedhash = digest.digest(textoOriginal.getBytes(StandardCharsets.UTF_8));

            return bytesToHex(encodedhash);

        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar hash", e);
        }
    }

    private String bytesToHex(byte[] hash) {
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

    private Response register(Object body) {
        System.out.println("[SERVER] registering a proxy server");
        proxyPublicKey = (PublicKey) body;
        return new Response(serverKeys.getPublic());
    }

    @Override
    public void run() {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            ServerSocket serverSocket = new ServerSocket(Ports.SERVER.getPort());
            System.out.println("[SERVER] servidor iniciado na porta " + Ports.SERVER.getPort());
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
            int tempPort = clientSocket.getPort();

            System.out.println("[SERVER] porta efemera solicitante " + tempPort);

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

            int originPort = request.origin();

            boolean canEnter = (boolean) requestToACL(new Request(request.origin(), TypeOfRequest.PROCEED, request.origin())).body();

            if (!canEnter) {
                System.out.println("[SERVER] " + tempPort + " -> " + originPort  + " bloqueada de entrar");
                clientSocket.close();
                return ;
            }

            System.out.println("[SERVER] requisicao aceita para a porta " + tempPort);

            boolean canExecute = (boolean) requestToACL(new Request(
                    new Request(request.origin(), request.type(), Ports.SERVER.getPort()), TypeOfRequest.EXECUTE, request.origin())
            ).body();

            if (!canExecute) {
                System.out.println("[SERVER] " + tempPort + " -> " + originPort + " bloqueada de executar por falta de privilegios");
                clientSocket.close();
                return ;
            }

            Response response;

            System.out.println("[SERVER] processando " + tempPort + " -> " + originPort + " requisitando " + request.type());

            switch (request.type()) {
                case DISCOVERY -> response = new Response(discover());
                case ACKNOWLEDGE -> response = new Response(getAuth(String.valueOf(originPort)));
                case REGISTER -> response = register(request.body());
                case SYNC -> response = sync(request.body());
                case EXCHANGE_PK -> response = registerEdge(request.body());
                default -> throw new RuntimeException("Invalid request type");
            }

            out.writeObject(response);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            clientSocket.close();
        }
    }

    private Response registerEdge(Object body) {
        this.edgePublicKey = (PublicKey) body;
        return new Response(serverKeys.getPublic());
    }

    private Response sync(Object body) {
        Map<TypeOfMeasurement, List<Double>> data = (Map<TypeOfMeasurement, List<Double>>) body;

        System.out.println(data);

        data.forEach((k, v) -> {
            var list = db.getOrDefault(k, new ArrayList<>());
            list.addAll(v);
            db.put(k, list);
        });

        return new Response(null);
    }
}
