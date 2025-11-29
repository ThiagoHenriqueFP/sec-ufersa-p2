package common;

import java.io.*;
import java.security.Key;

public class Utils {
    public static byte[] toByteArray(Object data) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);

        objectStream.writeObject(data);
        objectStream.flush();

        return byteStream.toByteArray();
    }

    public static Object deserialize(byte[] data) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bis)) {

            return ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException("Erro ao desserializar objeto", e);
        }
    }
}
