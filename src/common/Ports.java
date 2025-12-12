package common;

import java.util.Arrays;

public enum Ports {
    ACL(10101),
    EDGE(8080),
    SERVER(9876),
    PROXY_UDP(10102),
    PROXY_TCP(10103),
    CLIENT(9911),
    SENSOR_1(9901),
    SENSOR_2(9902),
    SENSOR_3(9903),
    SENSOR_4(9904);

    private final Integer port;

    Ports(Integer port) {
        this.port = port;
    }

    public static Ports from(int port) {
        return Arrays.stream(Ports.values()).filter(it -> it.getPort() == port).findFirst().orElse(null);
    }

    public Integer getPort() {
        return this.port;
    }
}
