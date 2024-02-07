
rule Trojan_BAT_AgentTesla_EXC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 44 00 } //01 00 
		$a_01_1 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 45 00 } //01 00 
		$a_01_2 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 46 00 } //01 00 
		$a_01_3 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 47 00 } //01 00 
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_5 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}