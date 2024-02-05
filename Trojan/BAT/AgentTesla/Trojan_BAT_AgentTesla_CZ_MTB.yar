
rule Trojan_BAT_AgentTesla_CZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 04 09 04 6f 90 01 04 5d 17 d6 28 90 01 04 da 2b 15 07 11 04 28 90 01 04 28 90 01 04 28 90 01 04 0b 2b 04 13 04 2b e7 09 17 d6 0d 2b 03 0c 2b c0 09 08 31 02 2b 05 2b bc 0b 2b ad 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}