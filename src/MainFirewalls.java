import firewall.acl.ACL;

void main() {
    ACL acl = new ACL();
    new Thread(acl).start();
}
