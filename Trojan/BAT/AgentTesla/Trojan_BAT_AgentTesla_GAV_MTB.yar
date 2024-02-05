
rule Trojan_BAT_AgentTesla_GAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 13 05 17 13 06 2b 30 02 6f 90 01 01 00 00 06 6f 90 01 01 00 00 0a 09 11 06 9a 6f 90 01 01 00 00 0a 00 02 6f 90 01 01 00 00 06 6f 90 01 01 00 00 0a 09 11 06 9a 6f 90 01 01 00 00 0a 26 11 06 17 d6 13 06 11 06 11 05 31 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}