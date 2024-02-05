
rule Ransom_Win32_Clop_SIB_MTB{
	meta:
		description = "Ransom:Win32/Clop.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 23 00 1f 00 00 14 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin Delete Shadows /all /quiet  14 00 
		$a_80_1 = {76 73 73 61 64 6d 69 6e 20 72 65 73 69 7a 65 20 73 68 61 64 6f 77 73 74 6f 72 61 67 65 20 2f 66 6f 72 3d 63 3a 20 2f 6f 6e 3d 63 3a 20 2f 6d 61 78 73 69 7a 65 3d } //vssadmin resize shadowstorage /for=c: /on=c: /maxsize=  01 00 
		$a_80_2 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 4d 65 73 73 61 67 65 20 52 6f 75 74 65 72 22 20 2f 79 } //net stop "Sophos Message Router" /y  01 00 
		$a_80_3 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 4d 43 53 20 43 6c 69 65 6e 74 22 20 2f 79 } //net stop "Sophos MCS Client" /y  01 00 
		$a_80_4 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 4d 43 53 20 41 67 65 6e 74 22 20 2f 79 } //net stop "Sophos MCS Agent" /y  01 00 
		$a_80_5 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 44 65 76 69 63 65 20 43 6f 6e 74 72 6f 6c 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "Sophos Device Control Service" /y  01 00 
		$a_80_6 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 43 6c 65 61 6e 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "Sophos Clean Service" /y  01 00 
		$a_80_7 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 57 65 62 20 43 6f 6e 74 72 6f 6c 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "Sophos Web Control Service" /y  01 00 
		$a_80_8 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 53 79 73 74 65 6d 20 50 72 6f 74 65 63 74 69 6f 6e 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "Sophos System Protection Service" /y  01 00 
		$a_80_9 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 41 67 65 6e 74 22 20 2f 79 } //net stop "Sophos Agent" /y  01 00 
		$a_80_10 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 41 75 74 6f 55 70 64 61 74 65 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "Sophos AutoUpdate Service" /y  01 00 
		$a_80_11 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 46 69 6c 65 20 53 63 61 6e 6e 65 72 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "Sophos File Scanner Service" /y  01 00 
		$a_80_12 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 53 61 66 65 73 74 6f 72 65 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "Sophos Safestore Service" /y  01 00 
		$a_80_13 = {6e 65 74 20 73 74 6f 70 20 22 53 6f 70 68 6f 73 20 48 65 61 6c 74 68 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "Sophos Health Service" /y  01 00 
		$a_80_14 = {6e 65 74 20 73 74 6f 70 20 73 6f 70 68 6f 73 73 70 73 20 2f 79 } //net stop sophossps /y  01 00 
		$a_80_15 = {6e 65 74 20 73 74 6f 70 20 4d 63 53 68 69 65 6c 64 20 2f 79 } //net stop McShield /y  01 00 
		$a_80_16 = {6e 65 74 20 73 74 6f 70 20 41 6e 74 69 76 69 72 75 73 20 2f 79 } //net stop Antivirus /y  01 00 
		$a_80_17 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 44 65 70 6c 6f 79 6d 65 6e 74 53 65 72 76 69 63 65 20 2f 79 } //net stop VeeamDeploymentService /y  01 00 
		$a_80_18 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 44 65 70 6c 6f 79 53 76 63 20 2f 79 } //net stop VeeamDeploySvc /y  01 00 
		$a_80_19 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 43 61 74 61 6c 6f 67 53 76 63 20 2f 79 } //net stop VeeamCatalogSvc /y  01 00 
		$a_80_20 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 42 61 63 6b 75 70 53 76 63 20 2f 79 } //net stop VeeamBackupSvc /y  01 00 
		$a_80_21 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 52 45 53 54 53 76 63 20 2f 79 } //net stop VeeamRESTSvc /y  01 00 
		$a_80_22 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 43 6c 6f 75 64 53 76 63 20 2f 79 } //net stop VeeamCloudSvc /y  01 00 
		$a_80_23 = {56 65 65 61 6d 20 42 61 63 6b 75 70 20 43 61 74 61 6c 6f 67 20 44 61 74 61 20 53 65 72 76 69 63 65 } //Veeam Backup Catalog Data Service  01 00 
		$a_80_24 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 4d 6f 75 6e 74 53 76 63 20 2f 79 } //net stop VeeamMountSvc /y  01 00 
		$a_80_25 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 48 76 49 6e 74 65 67 72 61 74 69 6f 6e 53 76 63 20 2f 79 } //net stop VeeamHvIntegrationSvc /y  01 00 
		$a_80_26 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 45 6e 74 65 72 70 72 69 73 65 4d 61 6e 61 67 65 72 53 76 63 20 2f 79 } //net stop VeeamEnterpriseManagerSvc /y  01 00 
		$a_80_27 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 54 72 61 6e 73 70 6f 72 74 53 76 63 20 2f 79 } //net stop VeeamTransportSvc /y  01 00 
		$a_80_28 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 4e 46 53 53 76 63 20 2f 79 } //net stop VeeamNFSSvc /y  01 00 
		$a_80_29 = {6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 42 72 6f 6b 65 72 53 76 63 20 2f 79 } //net stop VeeamBrokerSvc /y  01 00 
		$a_80_30 = {6e 65 74 20 73 74 6f 70 20 42 61 63 6b 75 70 45 78 65 63 41 67 65 6e 74 41 63 63 65 6c 65 72 61 74 6f 72 20 2f 79 } //net stop BackupExecAgentAccelerator /y  00 00 
	condition:
		any of ($a_*)
 
}