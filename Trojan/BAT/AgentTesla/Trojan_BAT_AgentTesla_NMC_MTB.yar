
rule Trojan_BAT_AgentTesla_NMC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 39 00 31 00 2e 00 32 00 34 00 33 00 2e 00 34 00 34 00 2e 00 31 00 34 00 32 00 2f } //01 00 
		$a_01_1 = {52 00 65 00 76 00 65 00 72 00 73 00 65 00 00 07 63 00 6d 00 64 } //01 00 
		$a_01_2 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 32 00 30 } //01 00 
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_4 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 73 } //00 00  GetMethods
	condition:
		any of ($a_*)
 
}