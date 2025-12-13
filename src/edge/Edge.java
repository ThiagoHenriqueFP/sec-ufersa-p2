package edge;

import client.TcpClient;
import common.*;
import sensors.TypeOfMeasurement;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static common.Crypto.getRsaKeyPar;

public class Edge implements Runnable {
    private PublicKey serverPublicKey;
    public KeyPair keys;

    private Integer sync = 0;
    private final Map<TypeOfMeasurement, List<Double>> db = new HashMap<>();

    public Edge() {
        try {
            keys = getRsaKeyPar();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        TcpClient client;

        client = new TcpClient(new Request(keys.getPublic(), TypeOfRequest.REGISTER, Ports.EDGE.getPort()), Ports.PROXY_TCP);
        client.run();

        Arrays.stream(TypeOfMeasurement.values()).forEach(type ->
                db.put(type, new ArrayList<>(10))
        );
    }

    synchronized public void parseToMap(String rawData) {

        String[] parts = rawData.split("\\|");

        TypeOfMeasurement[] tipos = TypeOfMeasurement.values();

        int limit = Math.min(parts.length, tipos.length);
        int i = 0;

        try {
            for (i = 0; i < limit; i++) {
                String cleanValue = parts[i].replaceAll("[^0-9.-]", "");

                if (!cleanValue.isEmpty()) {
                    double valor = Double.parseDouble(cleanValue);

                    List<Double> list = db.get(tipos[i]);
                    if (list.size() >= 10)
                        list.removeFirst();

                    list.add(valor);

                    db.put(tipos[i], list);
                }
            }
            ++sync;
            System.out.println(sync);
            if (sync == 10) {
                syncWithServer();
                sync = 0;
            }
        } catch (NumberFormatException e) {
            System.err.println("Erro ao converter valor: " + parts[i]);
        }
    }

    private void syncWithServer() {
        System.out.println("[EDGE] sincronizando " + db.values().stream().findFirst().orElse(new ArrayList<>()).size() + " dados com o servidor principal");
        TcpClient c = new TcpClient(new Request(db, TypeOfRequest.SYNC, Ports.EDGE.getPort()), serverPublicKey, Ports.SERVER);
        c.run();
    }

    @Override
    public void run() {
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            DatagramSocket socketServer = new DatagramSocket(Ports.EDGE.getPort());
            System.out.println("[EDGE] edge iniciada na porta " + Ports.EDGE.getPort());
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
                Object dataBytes = Utils.deserialize(Crypto.applyAuth(sp, keys.getPrivate()));
                if (dataBytes instanceof PublicKey) {
                    this.serverPublicKey = (PublicKey) dataBytes;
                } else {
                    String decriptedMessage = (String) dataBytes;
                    parseToMap(decriptedMessage);
                }
            } else {
                System.out.println("[EDGE] message not secured");
            }

        } catch (BadPaddingException e) {
            System.out.println("[EDGE] bad key provided");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
