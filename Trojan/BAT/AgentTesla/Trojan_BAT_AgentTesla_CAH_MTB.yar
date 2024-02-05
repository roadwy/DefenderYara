
rule Trojan_BAT_AgentTesla_CAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 90 01 01 00 00 06 05 03 17 58 05 8e 69 5d 91 28 90 01 01 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CAH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {09 11 04 6f 90 01 03 0a 13 05 07 11 05 28 90 01 03 0a 08 da 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 00 11 04 17 d6 13 04 11 04 09 6f 90 01 03 0a fe 04 13 06 11 06 2d c5 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}