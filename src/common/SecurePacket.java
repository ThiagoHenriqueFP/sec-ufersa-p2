package common;

import java.io.*;

public record SecurePacket(
        byte[] key,
        byte[] data
) implements Serializable {
    public byte[] toByteArray() throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);

        objectStream.writeObject(this);
        objectStream.flush();

        return byteStream.toByteArray();
    }

    public static SecurePacket fromByteArray(byte[] data) {
        try (ByteArrayInputStream byteStream = new ByteArrayInputStream(data);
             ObjectInputStream objectStream = new ObjectInputStream(byteStream)) {

            return (SecurePacket) objectStream.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}