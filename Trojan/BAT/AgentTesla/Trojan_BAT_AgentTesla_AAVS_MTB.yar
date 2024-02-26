
rule Trojan_BAT_AgentTesla_AAVS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 0a 06 28 90 01 01 00 00 0a 74 90 01 01 00 00 01 0b 07 20 5a 00 00 00 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 00 07 6f 90 01 01 00 00 0a 0c 08 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0d 09 6f 90 01 01 00 00 0a 13 04 11 04 28 90 01 01 00 00 0a 13 05 38 00 00 00 00 11 05 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}