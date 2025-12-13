import common.Ports;
import sensors.Sensor;

void main() throws Exception {
    Sensor sensor1 = new Sensor("localhost", Ports.SERVER, Ports.SENSOR_1, false, false);
    Sensor sensor2 = new Sensor("localhost", Ports.SERVER, Ports.SENSOR_2,true, false);
    Sensor sensor3 = new Sensor("localhost", Ports.SERVER, Ports.SENSOR_3, false, false);
    Sensor sensor4 = new Sensor("localhost", Ports.SERVER, Ports.SENSOR_4, false, true);

    new Thread(sensor1).start();
    new Thread(sensor2).start();
    new Thread(sensor3).start();
    new Thread(sensor4).start();
}