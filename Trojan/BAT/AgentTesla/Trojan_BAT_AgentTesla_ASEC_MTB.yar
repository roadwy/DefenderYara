
rule Trojan_BAT_AgentTesla_ASEC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 8e 69 17 da 13 08 16 0c 2b 20 11 04 08 17 8d 90 01 01 00 00 01 25 16 09 08 9a 1f 10 28 90 01 01 00 00 0a b4 9c 6f 90 01 01 00 00 0a 08 17 d6 0c 08 11 08 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}