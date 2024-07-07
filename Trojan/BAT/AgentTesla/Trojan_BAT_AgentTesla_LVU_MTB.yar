
rule Trojan_BAT_AgentTesla_LVU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 30 00 2e 00 35 00 31 00 2e 00 32 00 31 00 37 00 2e 00 31 00 31 00 33 00 2f 00 6b 00 6d 00 6e 00 2f 00 43 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 41 00 70 00 70 00 31 00 33 } //1
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_5 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}