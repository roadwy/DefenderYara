
rule Trojan_BAT_AgentTesla_LPQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 08 09 11 04 28 90 01 03 06 13 05 17 13 06 07 06 02 11 05 28 90 01 03 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 07 11 07 2d d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}