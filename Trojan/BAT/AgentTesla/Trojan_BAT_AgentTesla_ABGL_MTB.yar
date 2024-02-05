
rule Trojan_BAT_AgentTesla_ABGL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 06 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 18 8d 90 01 03 01 25 16 06 11 06 9a a2 25 17 1f 10 8c 90 01 03 01 a2 6f 90 01 03 0a a5 90 01 03 01 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d b2 90 00 } //01 00 
		$a_01_1 = {53 00 74 00 75 00 64 00 65 00 6e 00 74 00 43 00 6c 00 61 00 73 00 73 00 2e 00 56 00 53 00 46 00 56 00 } //00 00 
	condition:
		any of ($a_*)
 
}