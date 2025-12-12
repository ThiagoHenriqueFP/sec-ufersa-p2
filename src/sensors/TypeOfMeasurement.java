package sensors;

public enum TypeOfMeasurement {
    TEMPERATURE("°C", -10, 35),
    HUMIDITY("%", 30, 60),
    NOISE("dB", 30, 65),
    UV_RAD("UV", 0, 11),
    PM2_5("µg/m³", 0, 25),
    PM10("µg/m³", 0, 25),
    SO2("µg/m³", 0, 75),
    NO2("µg/m³", 0, 53),
    CO2("ppm", 400, 1000),
    CO("ppm", 0, 9);

    private String postfix;
    private float max;
    private float min;

    TypeOfMeasurement(String postfix, float min, float max) {
        this.postfix = postfix;
        this.max = max;
        this.min = min;
    }

    public String getPostfix() {
        return postfix;
    }

    public float getMax() {
        return max;
    }

    public float getMin() {
        return min;
    }
}
