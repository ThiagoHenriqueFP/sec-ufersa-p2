import firewall.ACL;

void main() {
    ACL acl = new ACL();
    new Thread(acl).start();
}
