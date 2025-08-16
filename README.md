**Server:**

sepc-vpn -l -p {VAULT_ADDRESS}

**Client:**

sepc-vpn -c {SERVER_IP} -p {VAULT_ADDRESS}

**A free use vault for {VAULT_ADDRESS} is available at https://www.hekateforge.com:8080/pool**


***AND***

**Don't forget to enable the interface and assign IPs**

**Server:**

sudo ifconfig sepc0 10.1.0.1 pointopoint 10.1.0.2 up

**Client**

sudo ifconfig sepc0 10.1.0.2 pointopoint 10.1.0.1 up
