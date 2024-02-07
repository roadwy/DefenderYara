
rule Trojan_BAT_SnakeKeylogger_SPRJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 9a 1f 10 28 90 01 03 0a d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 2a 11 2a 3a 8b fd ff ff 90 00 } //01 00 
		$a_01_1 = {57 00 46 00 43 00 75 00 62 00 65 00 41 00 74 00 74 00 61 00 63 00 6b 00 } //00 00  WFCubeAttack
	condition:
		any of ($a_*)
 
}