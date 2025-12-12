import firewall.ACL;
import firewall.Proxy;

void main() {
    ACL acl = new ACL();
    Proxy proxy = new Proxy();
    
    new Thread(acl).start();
    new Thread(proxy).start();
}
