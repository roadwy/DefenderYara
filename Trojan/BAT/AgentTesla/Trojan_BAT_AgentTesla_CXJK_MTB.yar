
rule Trojan_BAT_AgentTesla_CXJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 13 08 16 13 09 11 08 12 09 28 90 01 04 00 08 07 11 07 18 6f 90 01 04 1f 10 28 90 01 04 6f 90 01 04 00 de 0d 11 09 2c 08 11 08 28 90 01 04 00 dc 00 11 07 18 58 13 07 11 07 07 6f 90 01 04 fe 04 13 0a 11 0a 2d b2 90 00 } //01 00 
		$a_01_1 = {53 68 6f 7a 62 78 79 78 70 6f 6a 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}