
rule Trojan_BAT_AgentTesla_JTZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 0b 1f 56 8d 90 01 03 01 25 d0 90 01 03 04 28 90 01 03 0a 0c 28 90 01 03 0a 08 6f 90 01 03 0a 0d 09 28 90 01 03 06 13 04 1a 8d 90 01 03 01 13 07 11 07 16 72 90 01 03 70 a2 11 07 17 7e 90 01 03 0a a2 11 07 18 07 a2 11 07 19 17 8c 90 01 03 01 a2 11 07 13 05 14 13 06 11 04 28 90 00 } //01 00 
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_81_2 = {49 6e 73 74 61 6c 6c 55 74 69 6c } //00 00 
	condition:
		any of ($a_*)
 
}