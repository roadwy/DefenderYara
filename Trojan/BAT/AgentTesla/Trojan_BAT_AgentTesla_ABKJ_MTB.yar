
rule Trojan_BAT_AgentTesla_ABKJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 11 08 08 11 08 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 08 17 58 13 08 11 08 08 8e 69 fe 04 13 09 11 09 2d d9 90 00 } //01 00 
		$a_01_1 = {42 00 75 00 69 00 6c 00 64 00 45 00 76 00 65 00 6e 00 74 00 2e 00 52 00 43 00 53 00 41 00 57 00 } //00 00  BuildEvent.RCSAW
	condition:
		any of ($a_*)
 
}