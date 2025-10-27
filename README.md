# Security-Operation-Center-SOC-Azure-Environment-

Deploy a honeypot in an isolated Azure virtual environment and expose it to the public Internet in a controlled manner (with dedicated VNet isolation and narrowly scoped network rules); expect probes within minutes. Forward honeypot logs and failed-attempt events to a central repository, ingest them into Microsoft Sentinel, and run a KQL query to produce a geo-enriched attack map showing attack origins.

<img width="2096" height="1199" alt="Image" src="https://github.com/user-attachments/assets/35d4d7d6-e3b4-460f-bf42-66798617013e" />

Vnet-tobisoblab completed


<img width="2551" height="1133" alt="Image" src="https://github.com/user-attachments/assets/a3764dea-c106-4427-86a2-8f27165f447b" />


Azure Virtual Machine Deployed


<img width="1907" height="763" alt="Image" src="https://github.com/user-attachments/assets/62b5cfba-614b-4d51-b80a-6ac16f0254af" />


OTIT- virtual Machine

Vnet-Tobisoclab - Vnet


<img width="2556" height="916" alt="Image" src="https://github.com/user-attachments/assets/2e3ba440-5a0c-437f-830d-f31c23ecb714" />





Network Security group firewall - outbound and inbound rules set to ANY



<img width="2548" height="883" alt="Image" src="https://github.com/user-attachments/assets/de854f06-decf-40b2-aea2-9cb6d0dffc24" />


RDP to Access and switch off windows firewall 



<img width="2560" height="1296" alt="Image" src="https://github.com/user-attachments/assets/1f2c18d6-cc5d-4278-85f9-ba637ef31ec1" />



Outbound and inbound firewall OFF


<img width="1528" height="1032" alt="Image" src="https://github.com/user-attachments/assets/70dbadee-0a15-4d98-a418-be7169f2af9b" />



Ping Network - Indicates connection 


<img width="2392" height="1119" alt="Image" src="https://github.com/user-attachments/assets/86840720-45c6-485f-89a7-45db938ed4df" />


<img width="1560" height="1185" alt="Image" src="https://github.com/user-attachments/assets/c2131964-3e32-4ca3-83f7-38b27bd7bacd" />



Security Events via AMA - This will collect all the security events logs using Azure Monitor agent(AMA)



<img width="2556" height="1176" alt="Image" src="https://github.com/user-attachments/assets/07f659f6-d131-44cd-9c19-445bf7fd0b2c" />


Within just a few minutes , the VM scanned by more than 1,000 unique IP aadresses 



<img width="2521" height="1289" alt="Image" src="https://github.com/user-attachments/assets/f97ec55c-557b-49db-be4c-fb6fa81aa2c7" />


<img width="2505" height="1230" alt="Image" src="https://github.com/user-attachments/assets/b47db34d-a549-44da-a9dc-a050f6c14e1d" />




Performed OSINT investigation on a selected IP Address 


<img width="1546" height="601" alt="Image" src="https://github.com/user-attachments/assets/596e0a91-9fdd-4478-b6a7-da5c1766cec8" />


Abuse Percentage of 13%


<img width="2013" height="993" alt="Image" src="https://github.com/user-attachments/assets/063decd1-bb10-4f73-b2db-b83a0b8df212" />



<img width="2526" height="1223" alt="Image" src="https://github.com/user-attachments/assets/8d80b54d-1792-489e-893e-1f8bdf0affc1" />



After Running this Query 

let GeoIPDB_FULL == _Getwatchlist ("geoip")

let  WindowsEvents == securityEvent

     | where ipAddress == "210.222.67.2223"
     
     | wgere Event ID 4625 
     
     | order by TimeGenerated desc
     
     | evaluate ipv4_lookup (GeoIPDB_FULL, IpAddress, network);
     
WindownsEvents
| project TimeGenerated, computer, AttackIP,== cityname, countryname, latitude, longtide 

<img width="2540" height="1250" alt="Image" src="https://github.com/user-attachments/assets/40fd8f8e-8674-43ad-aa0d-f2777b035cc9" />




Sentinel Produces a geographic visualization showing the origins of the attacks


<img width="2528" height="1085" alt="Image" src="https://github.com/user-attachments/assets/f5282921-1825-4ee4-81b7-e37f7972da58" />







