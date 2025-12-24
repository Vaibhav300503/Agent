* ###### **TOOLS**

1. **Log Collection**

* Wazuh Agent: Windows / Linux
* Winlogbeat, Packetbeat, Filebeat



**2. Network /IDS**

* Zeek
* NetFlow / sFlow



**3. Transport \& Parsing**

* Logstash



**4. Storage**

* Elasticsearch (ELK Stack) / Opensearch



**5. Dashboard**

* Kibana + Wazuh App



**6. Threat Intel**

* MISP
* OTX
* VirusTotal



**7. SOAR / Case Management**

* TheHive + Cortex





* ###### **ARCHITECTURE**



1. Endpoints \& Sensors Wazuh agent on Windowds / Linux. Zeek.
2. Agents -> Wazuh Manager (agents register \& send events)
3. Wazuh Manager -> forward normalised alerts and raw events -> ELK
4. Logstash / ingest pipelines live on ingest nodes for heavy parsing / enrichment (Geo IP, Grok, threat intel)
5. Kibana dashboard + Wazuh App for dashboards, alert trage, rule management
6. Make backups / cold storage.



* ###### **Agent \& Deployment**

1. **Windows**

--- Use Wazuh MSI for mass deployment

--- Automate vis Group Policy, SCCM/Intune or Powershell + WinRM



**Linux (Ubuntu)**

--- Install Wazuh agent from repo and register with manager.



**2. Auto registration \& Credentials**

--- Use Wazuh agent auto-registration tokens to bulk-enroll endpoints.

**3. Network Devices / Firewalls / Proxies**

--- Send syslog -> central Logstash or syslog collector. Parse and forward to Elasticsearch.

**4. Testing \& Validating**

--- Validate events.

--- Confirm they appear on Kibana and trigger expected rules.



* ###### **CONNECTIVIY**

1. **Public IP with TLS**

--- Host the central Wazuh server (Ubuntu VM) on a cloud or a machine with a public IP.

* 1514/tcp – Wazuh agent connection (use TLS)
* 1515/tcp – Wazuh registration service
* 5601/tcp – Kibana (for SOC team, restrict by firewall)
* 9200/tcp – Elasticsearch (restrict to localhost)



**2. VPN**

* WireGuard
* Tailscale



