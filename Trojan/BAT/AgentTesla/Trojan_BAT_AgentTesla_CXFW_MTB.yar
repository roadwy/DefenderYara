
rule Trojan_BAT_AgentTesla_CXFW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 11 04 18 6f 90 01 04 13 05 07 11 04 18 5b 11 05 1f 10 28 90 01 04 9c 00 11 04 18 58 13 04 11 04 06 6f 90 01 04 fe 04 13 06 11 06 2d ce 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}