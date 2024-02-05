
rule Trojan_BAT_AgentTesla_NUG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 17 00 00 01 25 16 11 07 17 da 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 11 04 11 07 11 04 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 06 da 13 08 11 05 11 08 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 13 05 11 07 17 d6 13 07 90 00 } //01 00 
		$a_81_1 = {69 7e 7e 6e 7e 7e 76 7e 7e 6f 7e 7e 6b 7e 7e 65 } //01 00 
		$a_81_2 = {52 65 70 6c 61 63 65 } //01 00 
		$a_81_3 = {53 74 72 52 65 76 65 72 73 65 } //01 00 
		$a_81_4 = {53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 } //00 00 
	condition:
		any of ($a_*)
 
}