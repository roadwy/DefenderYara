
rule Trojan_BAT_AgentTesla_JXD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 9a 28 90 01 03 0a 23 90 01 08 59 28 90 01 03 0a b7 13 05 07 11 05 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 11 04 17 d6 13 04 11 04 09 31 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}