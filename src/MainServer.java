import common.Ports;
import dataCenter.Server;

void main() {
    Server server = new Server(Ports.SERVER);

    server.run();
}
