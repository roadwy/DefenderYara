
rule Trojan_BAT_AgentTesla_ABNU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 06 07 06 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 06 17 58 0a 06 07 8e 69 fe 04 13 08 11 08 2d df 90 00 } //01 00 
		$a_01_1 = {52 61 6e 67 65 72 55 70 2e 44 4a 4a 44 53 2e 72 65 73 6f 75 72 63 65 73 } //00 00  RangerUp.DJJDS.resources
	condition:
		any of ($a_*)
 
}