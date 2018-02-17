# GTScan
The Nmap Scanner for Telco. With the current focus on telecom security, there used tools in day to day IT side penetration testing should
be extended to telecom as well. From here came the motivation for an nmap-like scanner but for telco

The current security interconnect security controls might fail against reconnaissance , although mobile operators might implement 
SMS firewalls/proxies, Interconnect firewalls, some of those leak information that could be used for further information gathering
process.

The motivation behind this project, first adding a new toolking into the arsenal of telecom penetration testers. Second give the
mobile operators a way to test their controls to a primitive methodology such as information gathering and reconnaissance.

# How does it work
GTScan relies on using emtpy TCAP layers as probes to detect listening subsystem numbers (i.e application port numbers like 80 for
http, 443 for https but for telecom nodes) on the respective global titles. With this way will be able to map the network
and use the results to conduct targeted direct attacks to the respective nodes.

GTScan includes Message handling: Return message on error in the SCCP layer to determine from the response what is the scanned node.
If a TCAP abort message is returned with an error p-abortCause: unrecognizedMessageType (0) thus the destination nodes is listening
on the SSN that was scanned, else then the scanner continues scanning on other SSNs

You can provide GTscan a range of global titles to be scanned, a comma-separated or a single GT to be scanned, along with other
parameters

# Requirements
python3

pip3 install -r requirements.txt

And ofcourse an SS7/Sigtran access :)

# Usage

Example: ./GTScan.py -G 201500000000,201500000002 -g 965123456780 -c 1 -C 2 -p 2905 -P 2906 -l 192.168.56.1 -r 192.168.56.102

All contribustions are mostly welcomed
