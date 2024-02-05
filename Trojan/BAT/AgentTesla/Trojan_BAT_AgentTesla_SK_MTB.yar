
rule Trojan_BAT_AgentTesla_SK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 08 11 04 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 13 07 09 17 8d 82 00 00 01 25 16 11 07 9c 6f 90 01 03 0a 00 11 04 18 58 13 04 00 11 04 08 6f 90 01 03 0a fe 04 13 08 11 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}