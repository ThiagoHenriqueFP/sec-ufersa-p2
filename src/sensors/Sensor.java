package sensors;

import client.TcpClient;
import common.*;

import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.*;

import static common.Crypto.getRsaKeyPar;
import static common.Crypto.parsePublicKey;

public class Sensor implements Runnable {

    private String url;
    private int serverPort;
    private int clientPort;
    private int proxyPort;
    private String hash;
    private PublicKey proxyPublicKey;
    private PublicKey serverPublicKey;
    public static KeyPair keys;
    private final Random random = new Random();
    private final boolean wrongValues;

    static {

        try {

            keys = getRsaKeyPar();

        } catch (Exception e) {

            throw new RuntimeException(e);

        }
    }

    public Sensor(String url, Ports serverPort, Ports clientPort, boolean forceInsecure, boolean forceWrongValues) throws Exception {
        this.url = url;
        this.serverPort = serverPort.getPort();
        this.clientPort = clientPort.getPort();
        this.wrongValues = forceWrongValues;

        TcpClient client;
        Response response;

        client = new TcpClient(new Request(null, TypeOfRequest.ACKNOWLEDGE, this.clientPort), serverPort);
        client.run();
        response = client.getResponse();

        String[] responseBody = ((String) response.body()).split("<\\|>");

        this.hash = responseBody[0];
        this.proxyPublicKey = forceInsecure
                ? keys.getPublic()
                : parsePublicKey(responseBody[1].trim());

        this.serverPublicKey = parsePublicKey(responseBody[2].trim());

        client = new TcpClient(new Request(null, TypeOfRequest.DISCOVERY, this.clientPort), serverPublicKey, serverPort);
        client.run();
        response = client.getResponse();

        this.proxyPort = (Integer) response.body();

        System.out.println(this);
    }

    private String generate(TypeOfMeasurement type) {
        String postfix = type.getPostfix();
        float max = type.getMax();
        float min = type.getMin();

        if (wrongValues) {
            max += 3.5f;
            min -= 3.5f;
        }

        int valueInRange = (int) ((Math.random() * (max - min)) + min);

        return valueInRange + postfix;
    }

    private String getReport() {
        StringBuilder builder = new StringBuilder();
        Arrays
                .stream(TypeOfMeasurement.values())
                .forEach(
                        type -> builder
                                .append(this.generate(type))
                                .append(" | ")
                );

        return builder.toString();
    }

    @Override
    public void run() throws RuntimeException {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime end = now.plusMinutes(5);
        try (DatagramSocket socket = new DatagramSocket(clientPort)) {
            InetAddress addr = InetAddress.getByName(url);
            while (LocalDateTime.now().isBefore(end)) {
                String message = getReport();

                System.out.println("[SENSOR] message: " + message);

                SecurePacket sp = Crypto.getSecured(message, proxyPublicKey);
                byte[] buffer = Utils.toByteArray(sp);

                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, addr, proxyPort);
                socket.send(packet);

                int delay = random.nextInt(4001) + 1000;
                Thread.sleep(delay);

            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public String toString() {
        return "Sensor{" +
                "url='" + url + '\'' +
                ", port=" + serverPort +
                ", hash='" + hash + '\'' +
                ", edgePort=" + proxyPort +
                ", edgePublicKey=" + proxyPublicKey +
                ", serverPublicKey=" + serverPublicKey +
                ", random=" + random +
                '}';
    }
}
