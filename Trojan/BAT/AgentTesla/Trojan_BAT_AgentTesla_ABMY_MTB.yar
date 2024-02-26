
rule Trojan_BAT_AgentTesla_ABMY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 11 07 08 11 07 9a 1f 10 28 90 01 03 0a d2 9c 00 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d db 90 00 } //01 00 
		$a_01_1 = {54 00 61 00 6e 00 6b 00 42 00 61 00 74 00 74 00 6c 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  TankBattle.Properties.Resources
	condition:
		any of ($a_*)
 
}