
rule Trojan_BAT_AgentTesla_NDA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b 29 00 08 09 11 04 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 17 13 08 07 11 07 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 09 11 09 2d cc 90 00 } //0a 00 
		$a_03_1 = {13 04 2b 29 00 08 09 11 04 6f 90 01 03 0a 13 07 11 07 28 90 01 03 0a 13 08 17 13 09 07 11 08 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d cc 90 00 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}