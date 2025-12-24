#### **AGENTLESS MONITORING**





###### **SETUP**



* Agentless daemon - agentlessd
* Remote system access 
* MongoDB locally or remote server
* If needed, Logstash or Python, pymongo for data forwarding





###### **CONFIGURATION**



* Wazuh configuration - ossec.conf \[sudo nano /var/ossec/etc/ossec.conf]
* Add the block for agentless. For multiple devices add multiple separate blocks.
* For network devices - telnet\_check
* For Windows - wmi\_query





###### **WORKINGS**



* Wazuh manager connects to the remote system through SSH, Telnet, or WMI
* It initiates connection to target hosts.
* It executes commands or compares file integrity
* Wazuh decodes and correlates it using its ruleset.
* Results are written in json/ Dashboard





###### **PROTOCOLS \& TARGETS**



* SSH - Linux, network devices
* WMI - Windows systems
* Telnet - Routers, switches, firewalls





###### **LOG STORAGE**



**OPTIONS**



1. Install Logstash -> Install MongoDB plugin -> Create pipeline
2. Python Script collector: write a script \[This is a lightweight option]
3. Filebeat -> Logstash -> MongoDB pipeline \[similar to 1]



