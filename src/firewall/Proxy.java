package firewall;

import client.TcpClient;
import common.*;
import sensors.TypeOfMeasurement;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Proxy implements Runnable {

    private PublicKey serverPublicKey;
    private PublicKey edgePublicKey;
    private KeyPair proxyKeys;

    private Map<Integer, Integer> danger = new HashMap<>();

    public Proxy() {
        try {
            proxyKeys = Crypto.getRsaKeyPar();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private boolean inDanger(TypeOfMeasurement measurement, Double value) {
        float min = measurement.getMin();
        float max = measurement.getMax();

        return value < min || value > max;
    }

    private Response register(Request request) {
        if (request.origin() == Ports.SERVER.getPort()){
            System.out.println("[PROXY] registering a server in the proxy");
            serverPublicKey = (PublicKey) request.body();
            return new Response(proxyKeys.getPublic());
        } else if (request.origin() == Ports.EDGE.getPort()) {
            System.out.println("[PROXY] registering an edge in the proxy");
            edgePublicKey = (PublicKey) request.body();

            TcpClient client;

            client = new TcpClient(
                    new Request(edgePublicKey, TypeOfRequest.EXCHANGE_PK, Ports.EDGE.getPort())
            );
            client.run();
            // garantir o retorno da pk
            PublicKey serverPK = (PublicKey) client.getResponse().body();
            proxyToEdge(serverPK);

            return new Response(proxyKeys.getPublic());
        } else {
            return null;
        }
    }

    @Override
    public void run() {
        new Thread() {
            @Override
            public void run() {
                udp();
            }
        }.start();

        new Thread() {
            @Override
            public void run() {
                tcp();
            }
        }.start();
    }

    private void udp() {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            DatagramSocket socketServer = new DatagramSocket(Ports.PROXY_UDP.getPort());
            System.out.println("[PROXY] servidor UDP iniciado na porta " + Ports.PROXY_UDP.getPort());

            while (true) {
                DatagramPacket packet = new DatagramPacket(new byte[1024], 1024);
                socketServer.receive(packet);
                DatagramPacket finalPacket = packet;
                executor.submit(() -> {
                    try {
                        process(finalPacket);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                });
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void process(DatagramPacket packet) {
        try (ByteArrayInputStream byteStream = new ByteArrayInputStream(packet.getData());
             ObjectInputStream objectStream = new ObjectInputStream(byteStream)) {
            Object data = objectStream.readObject();

            if (data instanceof SecurePacket) {
                SecurePacket sp = (SecurePacket) data;
                String decriptedMessage = (String) Utils.deserialize(Crypto.applyAuth(sp, proxyKeys.getPrivate()));
                int port = packet.getPort();
                int dangerValues = this.danger.getOrDefault(port, 0);
                if (analyse(decriptedMessage)) {
                    this.danger.put(port, ++dangerValues);
                    System.out.println("[PROXY] received a danger value from " + port);
                } else {
                    this.danger.put(port, dangerValues == 0 ? 0 : --dangerValues);
                }

                if (dangerValues >= 10) {
                    System.out.println("[PROXY] blocking " + port);
                    this.danger.put(port, 10); // to limitando em 10 so p n virar bagunca;
                    return;
                }

                proxyToEdge(decriptedMessage);
                System.out.println("[PROXY] sending to edge from " + port);

            } else {
                System.out.println("[PROXY] message not secured");
            }

        } catch (BadPaddingException e) {
            System.out.println("[PROXY] bad key provided");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void tcp() {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            ServerSocket serverSocket = new ServerSocket(Ports.PROXY_TCP.getPort());
            System.out.println("[PROXY] servidor TCP iniciado na porta " + Ports.PROXY_TCP.getPort());
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
            System.out.println("[PROXY] servidor encerrando por falha");
            e.printStackTrace();
        }
    }

    private void process(Socket clientSocket) throws IOException {
        try {
            int tempPort = clientSocket.getPort();

            System.out.println("[PROXY] porta efemera solicitante " + tempPort);

            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            out.flush();

            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

            Object preParsed = in.readObject();
            Request request;

            if (preParsed instanceof SecurePacket) {
                byte[] rawBytes = Crypto.applyAuth((SecurePacket) preParsed, proxyKeys.getPrivate());

                request = (Request) Utils.deserialize(rawBytes);
            } else {
                request = (Request) preParsed;
            }

            Response response;
            int originPort = request.origin();
            System.out.println("[PROXY] processando " + tempPort + " -> " + originPort + " requisitando " + request.type());

            switch (request.type()) {
                case REGISTER -> response = register(request);
                default -> throw new RuntimeException("Invalid request type");
            }

            out.writeObject(response);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            clientSocket.close();
        }
    }

    private void proxyToEdge(String data) {
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress addr = InetAddress.getLocalHost();
                SecurePacket sp = Crypto.getSecured(data, edgePublicKey);
                byte[] buffer = Utils.toByteArray(sp);

                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, addr, Ports.EDGE.getPort());
                socket.send(packet);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void proxyToEdge(Object data) {
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress addr = InetAddress.getLocalHost();
                SecurePacket sp = Crypto.getSecured(data, edgePublicKey);
                byte[] buffer = Utils.toByteArray(sp);

                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, addr, Ports.EDGE.getPort());
                socket.send(packet);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    private boolean analyse(String rawData) {
        String[] parts = rawData.split("\\|");

        TypeOfMeasurement[] tipos = TypeOfMeasurement.values();

        int limit = Math.min(parts.length, tipos.length);

        for (int i = 0; i < limit; i++) {
            try {
                String cleanValue = parts[i].replaceAll("[^0-9.-]", "");

                if (!cleanValue.isEmpty()) {
                    double valor = Double.parseDouble(cleanValue);

                    if (inDanger(tipos[i], valor)){
                        System.out.println(tipos[i] + " received a danger value from " + valor);
                        return true;
                    }
                }
            } catch (NumberFormatException e) {
                System.err.println("Erro ao converter valor: " + parts[i]);
            }
        }
        return false;
    }
}
