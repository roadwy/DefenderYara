
rule Trojan_BAT_AgentTesla_CAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {26 20 02 00 00 00 38 90 01 04 11 04 11 00 18 5b 11 02 11 00 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 06 9c 20 03 00 00 00 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}