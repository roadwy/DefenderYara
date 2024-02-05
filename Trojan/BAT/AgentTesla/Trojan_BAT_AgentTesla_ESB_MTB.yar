
rule Trojan_BAT_AgentTesla_ESB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 07 17 da 28 90 01 03 06 28 90 01 03 06 11 04 11 07 11 04 28 90 01 03 06 5d 28 90 01 03 06 28 90 01 03 06 da 13 08 11 05 11 08 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 13 05 11 07 17 d6 13 07 90 00 } //01 00 
		$a_01_1 = {53 00 74 00 72 00 69 00 6e 00 67 00 31 00 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}