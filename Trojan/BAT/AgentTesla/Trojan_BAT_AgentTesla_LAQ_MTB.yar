
rule Trojan_BAT_AgentTesla_LAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {08 06 07 6f 90 01 03 0a 26 08 06 07 6f 90 01 03 0a 13 09 11 09 28 90 01 03 0a 13 0a 11 04 09 11 0a 28 90 01 03 0a 9c 07 17 58 0b 07 08 6f 90 01 03 0a fe 04 13 0b 11 0b 2d 90 00 } //04 00 
		$a_03_1 = {08 09 11 04 6f 90 01 03 0a 13 08 08 09 11 04 6f 90 01 03 0a 13 09 11 09 28 90 01 03 0a 13 0a 07 06 11 0a 28 90 01 03 0a 9c 00 11 04 17 58 13 04 11 04 08 6f 90 01 03 0a fe 04 13 0b 11 0b 2d bf 90 00 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}