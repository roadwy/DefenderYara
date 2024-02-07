
rule Trojan_BAT_AgentTesla_MBIY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 72 00 69 00 6e 00 67 00 31 00 00 05 2a 00 2a 00 00 03 7e 00 00 03 3a 00 00 05 7d 00 7d 00 00 03 7d 00 00 09 4c 00 6f 00 61 00 64 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_4 = {53 70 6c 69 74 } //00 00  Split
	condition:
		any of ($a_*)
 
}