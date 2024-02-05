
rule Trojan_BAT_AgentTesla_DQY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DQY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 11 05 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 13 09 17 13 0a 00 08 07 11 09 d2 9c 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0b 11 0b 2d cd 90 00 } //01 00 
		$a_01_1 = {00 45 58 30 30 30 30 31 00 } //01 00 
		$a_01_2 = {00 45 58 30 30 30 30 32 00 } //01 00 
		$a_01_3 = {00 54 6f 57 69 6e 33 32 00 } //01 00 
		$a_01_4 = {00 47 65 74 50 69 78 65 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}