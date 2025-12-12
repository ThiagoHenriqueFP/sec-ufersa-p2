package client;

import common.*;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PublicKey;

public class TcpClient implements Runnable {

    private final Request request;
    private Response response;
    private PublicKey pk;
    private Ports hostPort;

    public TcpClient(Request request) {
        this.request = request;
        this.hostPort = Ports.SERVER;
    }

    public TcpClient(Request request, PublicKey publicKey, Ports hostPort) {
        this.request = request;
        this.pk = publicKey;
        this.hostPort = hostPort;
    }

    public TcpClient(Request request, Ports hostPort) {
        this.request = request;
        this.hostPort = hostPort;
    }

    public Response getResponse() {
        return response;
    }

    @Override
    public void run() {
        try (Socket socket = new Socket("localhost", hostPort.getPort());
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.flush();

            if (pk != null) {
                SecurePacket sp = Crypto.getSecured(request, pk);
                out.writeObject(sp);
                System.out.println("[TCP_CLIENT] sending secure packet " + sp);
            } else {
                out.writeObject(request);
                System.out.println("[TCP_CLIENT] sending insecure packet " + request);
            }

            Object preParsed = in.readObject();

            if (preParsed instanceof Response)
                response = (Response) preParsed;
            else if (preParsed == null)
                response = null;

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
