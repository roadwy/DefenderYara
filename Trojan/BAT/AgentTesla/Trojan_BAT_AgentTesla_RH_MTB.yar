
rule Trojan_BAT_AgentTesla_RH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 9a 13 04 7e 90 01 04 17 8d 90 01 03 01 25 16 1f 24 9d 6f 90 01 03 0a 13 05 19 8d 90 01 03 01 25 16 11 05 16 9a a2 25 17 11 05 17 9a a2 25 18 72 90 01 04 a2 13 06 11 04 11 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}