
rule Ransom_Win32_Babuk_SIB_MTB{
	meta:
		description = "Ransom:Win32/Babuk.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 17 00 0f 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin.exe delete shadows /all /quiet  20
		$a_80_1 = {62 61 62 75 6b 20 72 61 6e 73 6f 6d 77 61 72 65 20 67 72 65 65 } //babuk ransomware gree  10
		$a_80_2 = {2e 6f 6e 69 6f 6e } //.onion  1
		$a_80_3 = {2e 62 61 62 79 6b } //.babyk  1
		$a_80_4 = {42 61 63 6b 75 70 45 78 65 63 56 53 53 50 72 6f 76 69 64 65 72 } //BackupExecVSSProvider  1
		$a_80_5 = {42 61 63 6b 75 70 45 78 65 63 41 67 65 6e 74 41 63 63 65 6c 65 72 61 74 6f 72 } //BackupExecAgentAccelerator  1
		$a_80_6 = {42 61 63 6b 75 70 45 78 65 63 41 67 65 6e 74 42 72 6f 77 73 65 72 } //BackupExecAgentBrowser  1
		$a_80_7 = {42 61 63 6b 75 70 45 78 65 63 44 69 76 65 63 69 4d 65 64 69 61 53 65 72 76 69 63 65 } //BackupExecDiveciMediaService  1
		$a_80_8 = {42 61 63 6b 75 70 45 78 65 63 4a 6f 62 45 6e 67 69 6e 65 } //BackupExecJobEngine  1
		$a_80_9 = {42 61 63 6b 75 70 45 78 65 63 4d 61 6e 61 67 65 6d 65 6e 74 53 65 72 76 69 63 65 } //BackupExecManagementService  1
		$a_80_10 = {42 61 63 6b 75 70 45 78 65 63 52 50 43 53 65 72 76 69 63 65 } //BackupExecRPCService  1
		$a_80_11 = {56 65 65 61 6d 54 72 61 6e 73 70 6f 72 74 53 76 63 } //VeeamTransportSvc  1
		$a_80_12 = {56 65 65 61 6d 44 65 70 6c 6f 79 6d 65 6e 74 53 65 72 76 69 63 65 } //VeeamDeploymentService  1
		$a_80_13 = {56 65 65 61 6d 4e 46 53 53 76 63 } //VeeamNFSSvc  1
		$a_80_14 = {76 65 65 61 6d } //veeam  1
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1) >=23
 
}