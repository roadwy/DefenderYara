
rule Trojan_BAT_AgentTesla_ASAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 8e 69 17 da 13 08 16 13 09 2b 1c 11 04 11 09 09 11 09 9a 1f 10 28 90 01 01 00 00 0a b4 6f 90 01 01 00 00 0a 00 11 09 17 d6 13 09 11 09 11 08 31 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}