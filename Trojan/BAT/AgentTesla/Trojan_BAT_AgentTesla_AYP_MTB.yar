
rule Trojan_BAT_AgentTesla_AYP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {17 da 13 07 16 13 04 2b 2f 08 09 11 04 90 01 05 13 08 08 09 11 04 90 01 05 13 09 11 09 90 01 05 13 0a 07 06 11 0a 90 01 05 9c 11 04 17 d6 13 04 11 04 11 07 31 cb 06 17 d6 0a 09 17 d6 0d 09 11 06 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}