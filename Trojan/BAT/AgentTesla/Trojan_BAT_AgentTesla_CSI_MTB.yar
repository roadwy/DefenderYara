
rule Trojan_BAT_AgentTesla_CSI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2d 03 26 2b 03 0b 2b 00 73 90 01 03 0a 06 6f 90 01 03 0a 90 02 02 2d 22 26 07 08 6f 90 01 03 0a 07 18 6f 90 01 03 0a 07 6f 90 01 03 0a 03 16 03 8e 69 6f 90 01 03 0a 0d de 15 0c 2b dc 07 6f 90 01 03 0a dc 90 00 } //1
		$a_01_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 } //1 GetManifestResource
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_3 = {41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //1 AssemblyResolve
		$a_01_4 = {00 43 6c 61 73 73 4c 69 62 72 61 72 79 00 } //1 䌀慬獳楌牢牡y
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}