package common;

public enum Ports {
    EDGE(8080),
    SERVER(9876),
    SENSOR_1(9901),
    SENSOR_2(9902),
    SENSOR_3(9903),
    SENSOR_4(9904);

    private final Integer port;

    Ports(Integer port) {
        this.port = port;
    }

    public Integer getPort() {
        return this.port;
    }
}
