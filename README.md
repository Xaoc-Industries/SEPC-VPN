**Installer**

*The installer is a shell script contained in a zip folder.*

*to install, **YOU MUST RUN AS ROOT** afer extracting from the zip*

**If you open the sh in a text editor, it will bork the editor 99% of the time due to the sh file containing a base64 copy of the binary**

once you extract, you must chmod +x the sh file.

**Server:**

sudo sepc-vpn -l

**Client:**

sudo sepc-vpn -c {SERVER_IP}

**A free use vault for {VAULT_ADDRESS} is available at https://www.hekateforge.com:8080/pool**


***AND***

**Don't forget to enable the interface and assign IPs**

**Server:**

sudo ifconfig sepc0 10.1.0.1 pointopoint 10.1.0.2 up

**Client**

sudo ifconfig sepc0 10.1.0.2 pointopoint 10.1.0.1 up
