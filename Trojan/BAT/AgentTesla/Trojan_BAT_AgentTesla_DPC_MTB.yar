
rule Trojan_BAT_AgentTesla_DPC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 26 00 08 09 11 04 28 90 01 03 06 13 05 11 05 28 90 01 03 0a 13 06 07 06 11 06 28 90 01 03 0a 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 07 11 07 2d cf 06 17 58 0a 00 09 17 58 0d 09 20 00 56 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}