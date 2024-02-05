
rule Trojan_BAT_AgentTesla_ABFQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 07 06 9a 1f 10 28 90 01 03 0a 8c 90 01 03 01 6f 90 01 03 0a 26 06 17 58 0a 06 07 8e 69 fe 04 13 09 11 09 2d da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}