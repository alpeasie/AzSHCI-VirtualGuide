# AzSHCI-VirtualGuide
Prep an 22H2 HCI cluster for deployment using an Azure VM and the new deployment experience in WAC-Lite.

Step 1: Deploy a new VM using the following template. 
 - I recommend using the default VM size: Standard_E8s_v4. 
 - Leave the username as AzureAdmin. 
 - This will take about 30 minutes to deploy. Don't connect to the VM until you see the "deployment succeeded green checkmark" (screenshot below)

https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Falpeasie%2FAzSHCI-VirtualGuide%2Fmain%2FDeployment%2Fjson%2Fazuredeploy.json


![image](https://user-images.githubusercontent.com/34490917/212423319-3208868c-5b1c-4fc4-a97f-2449845d9aa3.png)




Step 2: Download the RDP file for the VM and sign in using 
  username: \AzureAdmin 
  password: Whatever password you provide


Step 3: Run the "PrepHostForDeployment" script on desktop. 

 - If the powershell window looks like it's freezing, click on the windowo and type in a key on your keyboard. This should unfreeze this script. 
 - The script takes about 1-2 hours to run. 


![image](https://user-images.githubusercontent.com/34490917/212422506-5e4fe716-ea97-425c-ba41-771f8cce1d9b.png)


Step 4: Launch the deployment tool. Open up edge and type in https://192.168.0.3 to launch the deployment wizard in WAC-Lite. 

 - Sign in to the seed node using the local admin credentials:
   username: Administrator
   password: 
   
   
   
   

Deployment guide (To be updated with new instructions in January) 

Step 1.3
  - Provide the local adminstrator credentails. 
  - Add the IP addresses for both nodes: 192.168.0.3 and 192.168.0.4

![image](https://user-images.githubusercontent.com/34490917/212424329-0dac8ae6-26ff-48dd-b5c0-8baba71c739a.png)



Step 1.5: 
  - Type in the info from the screenshot below
  domain: cosei.com
  AD prefis: hci
  AD OU: OU=contoso,DC=cosei,DC=com
  Username: AzureAdmin
  Password: 
  
  
 Step 2.1: Leave default values
 
 Step 2.2 
  
 ![image](https://user-images.githubusercontent.com/34490917/212424816-e5ae48ca-1513-4e5f-bac3-368e16987f9c.png)


Define network intents:

![image](https://user-images.githubusercontent.com/34490917/212426069-8d34a31b-c56d-4f4d-a78e-071860db0757.png)



Allocate IP addresses

![image](https://user-images.githubusercontent.com/34490917/212426551-389203c6-55de-4005-9ace-9ec94f6590fb.png)


Cluster name: cluster1

Save the config file to redeploy if you have issues
