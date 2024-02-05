
rule Trojan_BAT_AgentTesla_CXRG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 6f 74 00 00 0a 13 0b 12 0b 28 90 01 04 13 0c 07 11 05 11 0c 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f 90 01 04 fe 04 13 0d 11 0d 2d c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}