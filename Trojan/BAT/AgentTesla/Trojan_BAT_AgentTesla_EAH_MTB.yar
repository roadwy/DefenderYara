
rule Trojan_BAT_AgentTesla_EAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 07 95 28 90 01 03 0a 0c 16 0d 2b 0e 06 07 1a 5a 09 58 08 09 91 9c 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d e6 00 07 17 58 0b 90 00 } //01 00 
		$a_01_1 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 } //01 00 
		$a_01_2 = {00 43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EAH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 11 08 11 04 07 11 04 9a 1f 10 28 90 01 01 00 00 0a d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 2a 11 2a 3a 90 00 } //02 00 
		$a_01_1 = {16 13 05 11 05 16 fe 01 13 12 11 12 2c 05 17 13 05 2b 12 16 25 13 05 13 13 11 13 2c 05 17 13 05 2b 03 17 13 05 17 13 06 11 06 16 fe 01 13 14 11 14 2c 05 17 13 06 2b 12 } //01 00 
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_3 = {53 70 6c 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}