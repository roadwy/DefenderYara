
rule Trojan_BAT_AgentTesla_PSZW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {38 55 ff ff ff 11 01 11 0b 16 28 90 01 01 00 00 06 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}