package firewall.acl;

import common.*;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ACL implements Runnable {

    private static PublicKey serverPublicKey;
    private static KeyPair aclKeys;

    static {
        try {
            aclKeys = Crypto.getRsaKeyPar();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private final List<TypeOfRequest> server = List.of();
    private final List<TypeOfRequest> sensor = List.of();

    private final List<TypeOfRequest> client = List.of(TypeOfRequest.RETRIEVE);
    private final List<TypeOfRequest> edge = List.of(TypeOfRequest.REGISTER, TypeOfRequest.SYNC);
    private final List<Ports> blocked = new ArrayList<>();

    private Map<Ports, List<TypeOfRequest>> rules = new HashMap<>() {{
        put(Ports.SENSOR_1, sensor);
        put(Ports.SENSOR_2, sensor);
        put(Ports.SENSOR_3, sensor);
        put(Ports.SENSOR_4, sensor);
        put(Ports.SERVER, server);
        put(Ports.CLIENT, client);
        put(Ports.EDGE, edge);
    }};

    public Response canEnter(Object data) {
        Ports fromConnection = Ports.from((int) data);
        boolean permit = fromConnection != null && !blocked.contains(fromConnection);

        return new Response(permit);
    }

    public Response canExecute(Object data) {
        Request request = (Request) data;
        var accesses = rules.get(Ports.from((int) request.body()));
        if (accesses == null)
            return new Response(false);;

        TypeOfRequest type = accesses.stream().filter(it -> it == request.type()).findFirst().orElse(null);

        if (type == null)
            return new Response(false);

        return new Response(true);
    }

    public Response block(Object data) {
        Ports port = (Ports) data;
        if (!blocked.contains(port))
            blocked.add(port);

        return new Response(null);
    }

    public Response unblock(Object data) {
        Ports port = (Ports) data;
        blocked.remove(port);
        return new Response(null);
    }

    private Response register(Object body) {
        System.out.println("[ACL] registering a main server");
        serverPublicKey = (PublicKey) body;
        return new Response(aclKeys.getPublic());
    }

    @Override
    public void run() {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            ServerSocket serverSocket = new ServerSocket(Ports.ACL.getPort());
            System.out.println("[ACL] servidor iniciado na porta " + Ports.ACL.getPort());
            while (true) {
                Socket clientSocket = serverSocket.accept();

                executor.submit(() -> {
                    try {
                        System.out.println("[ACL] trying to process");
                        process(clientSocket);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
            }
        } catch (IOException e) {
            System.out.println("[ACL] servidor encerrando por falha");
            e.printStackTrace();
        }
    }

    private void process(Socket clientSocket) throws IOException {
        try {
            int port = clientSocket.getPort();

            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            out.flush();

            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

            Object preParsed = in.readObject();
            Request request;

            if (preParsed instanceof SecurePacket) {
                byte[] rawBytes = Crypto.applyAuth((SecurePacket) preParsed, aclKeys.getPrivate());

                request = (Request) Utils.deserialize(rawBytes);
            } else {
                request = (Request) preParsed;
            }

            Response response;
            System.out.println("[ACL] processando " + port + " requisitando " + request.type());

            switch (request.type()) {
                case REGISTER -> response = register(request.body());
                case EXECUTE -> response = canExecute(request.body());
                case PROCEED -> response = canEnter(request.body());
                case UNBLOCK -> response = unblock(request.body());
                case BLOCK -> response = block(request.body());
                default -> throw new RuntimeException("Invalid request type");
            }

            out.writeObject(response);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            clientSocket.close();
        }
    }
}
