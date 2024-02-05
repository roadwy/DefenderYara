
rule Trojan_BAT_AgentTesla_CSM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a d2 6f 90 01 03 0a 08 17 58 0c 08 06 6f 90 01 03 0a 18 5b fe 04 0d 09 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_2 = {54 6f 49 6e 74 33 32 } //01 00 
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //01 00 
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_5 = {47 65 74 44 6f 6d 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}