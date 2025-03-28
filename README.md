## **Data Exfiltration from PIP'd Employee** 
![image](https://github.com/user-attachments/assets/c85a3561-c4ef-4f1c-a81f-fa6df8a3bbfe)



# 🎯 **Use Case**   

## 📚 **Scenario:**  
An employee named John Doe, working in a sensitive department, was recently placed on a performance improvement plan (PIP). After displaying concerning behavior, management suspects John may be planning to steal proprietary information and leave the company. The investigation involves analyzing activities on John’s corporate device (`windows-target-1`) using Microsoft Defender for Endpoint (MDE).  

<b>Note: John is an administrator on his device and is not limited on which applications he uses.</b>


---

## 📊 **Incident Summary and Findings**  

### **Timeline Overview**  
1. **🔍 Archiving Activity:**  
   - **Observed Behavior:** Frequent creation of `.zip` files in a folder labeled "backup."  
   - **Detection Query (KQL):**  
     ```kql
     DeviceFileEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceNetworkEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceProcessEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceFileEvents
     | where DeviceName == "windows-target-1"
     | where FileName endswith ".zip"
     | order by Timestamp desc
     ```
![image](https://github.com/user-attachments/assets/e723f145-416d-4be6-bb7a-c5604ff268d4)


     
2. **⚙️ Process Analysis:**  
   - **Observed Behavior:** I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 mintutes after. I discoverd around the same time, that apowershellscript silently installed 7zip and then used 7zip to zip up employee data into an archive.
   - **Detection Query (KQL):**  

     ```kql
     let VMName = "windows-target-1";
     let specificTime = datetime(2025-03-28T16:50:36.4906941Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     | project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
     ```
![image](https://github.com/user-attachments/assets/5d722511-ebf0-44e2-a1cb-19e4c802bc20)



   3. **🌐 Network Exfiltration Check:**  
   - **Observed Behavior:** searched around the same time period for any evidence of exfiltration from the network, but did not see any logs indicating as such.  

   - **Detection Query (KQL):**  

     ```kql
     let VMName = "windows-target-1";
     let specificTime = datetime(2025-03-28T16:50:36.4906941Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 5m) .. (specificTime + 5m))
     | where DeviceName == VMName
     | order by Timestamp desc
     ```  

4. **📝 Response:**  
   - Shared findings with the manager, highlighting automated archive creation, however, no signs of any data being exfiltrated.
   - The device was immediately isolated, and awaiting further instructions on how to proceed.

---

## 🛡️ **MITRE ATT&CK Framework TTPs**  
<!--
| **Tactic**           | **Technique**                                                                                     | **ID**            | **Description**                                                                                                                                                 |  
|-----------------------|---------------------------------------------------------------------------------------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| 💻 **Initial Access**| Application Layer Protocol: Web Protocols                                                        | T1071.001          | PowerShell was utilized to install necessary software, indicating potential use of web protocols for initial access activities.                                |
| 🛠️ **Execution**      | PowerShell                                                                                       | T1059.001         | PowerShell scripts were used to silently install 7-Zip and execute file compression commands.                                                                   |  
| 🔒 **Persistence**    | Create or Modify System Process: Windows Service                                                 | T1543.003         | Installation of 7-Zip may serve as a persistence mechanism for continuous use.                                                                                   |
| 🔍 **Discovery**       | File and Directory Discovery                                                                    | T1083             | Activities point toward the discovery of sensitive files, likely for exfiltration purposes.                                                                     |  
| 📦 **Collection**      | Archive Collected Data                                                                           | T1560.001         | Employee data was compressed into `.zip` files using 7-Zip, possibly for easier handling or exfiltration.                                                       |  
| 📂 **Exfiltration**    | Exfiltration Over Alternative Protocol                                                           | T1048             | Although no network exfiltration was detected, the technique aligns with the potential misuse of alternate protocols for stealthy data transfer.                |  
| 💥 **Impact**          | Data Encrypted for Impact                                                                        | T1486             | The archive creation could signal an attempt to prepare files for encryption or exfiltration                                                                    | 
-->

<table>
  <thead>
    <tr>
      <th>Tactic</th>
      <th>Technique</th>
      <th>ID</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>💻 Initial Access</td>
      <td>Application Layer Protocol: Web Protocols</td>
      <td>T1071.001</td>
      <td>PowerShell was utilized to install necessary software, indicating potential use of web protocols for initial access activities.</td>
    </tr>
    <tr>
      <td>🛠️ Execution</td>
      <td>PowerShell</td>
      <td>T1059.001</td>
      <td>PowerShell scripts were used to silently install 7-Zip and execute file compression commands.</td>
    </tr>
    <tr>
      <td>🔒 Persistence</td>
      <td>Create or Modify System Process: Windows Service</td>
      <td>T1543.003</td>
      <td>Installation of 7-Zip may serve as a persistence mechanism for continuous use.</td>
    </tr>
    <tr>
      <td>🔍 Discovery</td>
      <td>File and Directory Discovery</td>
      <td>T1083</td>
      <td>Activities point toward the discovery of sensitive files, likely for exfiltration purposes.</td>
    </tr>
    <tr>
      <td>📦 Collection</td>
      <td>Archive Collected Data</td>
      <td>T1560.001</td>
      <td>Employee data was compressed into <code>.zip</code> files using 7-Zip, possibly for easier handling or exfiltration.</td>
    </tr>
    <tr>
      <td>📂 Exfiltration</td>
      <td>Exfiltration Over Alternative Protocol</td>
      <td>T1048</td>
      <td>Although no network exfiltration was detected, the technique aligns with the potential misuse of alternate protocols for stealthy data transfer.</td>
    </tr>
    <tr>
      <td>💥 Impact</td>
      <td>Data Encrypted for Impact</td>
      <td>T1486</td>
      <td>The archive creation could signal an attempt to prepare files for encryption or exfiltration.</td>
    </tr>
  </tbody>
</table>


---

### 🧑‍💻 **Next Steps**  
1. Monitor John’s account activity for unusual access or privilege escalation.  
2. Implement DLP (Data Loss Prevention) measures to alert on potential data exfiltration.  
3. Escalate findings to management and recommend a follow-up review of John's device for additional forensic artifacts.  

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

<b>Note: Powershell Script utilized to generate fake employee data and compress the file can be found [here]()

---

## Created By:
- **Author Name**: Winston Hibbert
- **Author Contact**: www.linkedin.com/in/winston-hibbert-262a44271/
- **Date**: March 28, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 28, 2025`  | `Trevino Parker`   
