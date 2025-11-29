import common.Ports;
import sensors.Sensor;

void main() throws Exception {
    Sensor sensor1 = new Sensor("localhost", Ports.SERVER, false);
    Sensor sensor2 = new Sensor("localhost", Ports.SERVER, true);

    new Thread(sensor1).start();
    new Thread(sensor2).start();
}