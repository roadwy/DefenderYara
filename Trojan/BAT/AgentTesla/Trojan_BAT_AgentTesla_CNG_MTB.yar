
rule Trojan_BAT_AgentTesla_CNG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 14 72 ca 51 02 70 18 8d 90 01 04 25 16 72 90 01 04 a2 25 17 72 90 01 04 a2 90 02 03 28 90 01 04 14 72 90 01 04 18 8d 90 01 04 25 16 72 90 01 04 a2 25 17 72 90 01 04 a2 90 02 03 28 90 01 04 14 72 90 01 04 18 8d 90 01 04 25 16 72 90 01 04 a2 25 17 72 90 01 04 a2 90 02 03 28 90 01 04 28 90 01 04 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}