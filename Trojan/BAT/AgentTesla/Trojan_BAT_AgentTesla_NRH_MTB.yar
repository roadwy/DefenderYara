
rule Trojan_BAT_AgentTesla_NRH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 05 17 da 6f 90 01 03 0a 08 11 05 08 6f 90 01 03 0a 5d 6f 90 01 03 0a da 13 06 09 11 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0d 11 05 17 d6 13 05 11 05 11 04 31 c5 90 00 } //01 00 
		$a_01_1 = {77 00 77 00 77 00 77 00 77 00 77 00 77 00 77 00 77 00 } //01 00  wwwwwwwww
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_3 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}