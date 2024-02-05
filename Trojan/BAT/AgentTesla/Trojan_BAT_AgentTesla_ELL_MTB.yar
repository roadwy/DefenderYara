
rule Trojan_BAT_AgentTesla_ELL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ELL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 0a 06 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 0b 07 6f 90 01 03 0a 07 6f 90 01 03 0a 20 00 01 00 00 14 14 14 6f 90 01 03 0a 75 90 01 03 01 28 90 01 03 0a 26 00 2a 90 09 09 00 7e 90 01 03 04 75 90 00 } //01 00 
		$a_01_1 = {00 47 65 74 4d 65 74 68 6f 64 00 } //01 00 
		$a_01_2 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_3 = {00 47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}