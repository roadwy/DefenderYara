
rule Trojan_BAT_AgentTesla_ABGS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 06 06 11 06 9a 1f 10 28 90 01 03 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de 90 00 } //01 00 
		$a_01_1 = {4c 00 69 00 67 00 68 00 74 00 73 00 4f 00 75 00 74 00 2e 00 46 00 56 00 57 00 53 00 46 00 57 00 } //00 00  LightsOut.FVWSFW
	condition:
		any of ($a_*)
 
}