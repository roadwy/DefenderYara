
rule Trojan_BAT_AgentTesla_NGP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 00 32 00 32 00 33 00 32 00 31 00 33 00 31 00 32 00 78 00 30 00 30 00 30 00 32 00 33 00 33 00 32 } //1
		$a_01_1 = {68 64 66 66 64 65 65 66 61 73 } //1 hdffdeefas
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}