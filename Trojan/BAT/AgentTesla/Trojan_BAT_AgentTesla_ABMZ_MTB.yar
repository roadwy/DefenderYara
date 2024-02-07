
rule Trojan_BAT_AgentTesla_ABMZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 06 00 "
		
	strings :
		$a_03_0 = {07 11 05 06 11 05 9a 1f 10 28 90 01 03 0a d2 9c 00 11 05 17 58 13 05 11 05 06 8e 69 fe 04 13 06 11 06 2d db 90 00 } //01 00 
		$a_01_1 = {4e 00 74 00 68 00 2e 00 45 00 69 00 6e 00 64 00 68 00 6f 00 76 00 65 00 6e 00 2e 00 46 00 6f 00 6e 00 74 00 79 00 73 00 2e 00 7a 00 65 00 } //00 00  Nth.Eindhoven.Fontys.ze
	condition:
		any of ($a_*)
 
}