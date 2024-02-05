
rule Trojan_BAT_AgentTesla_CDA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {da 13 04 06 11 04 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 09 17 d6 0d 09 08 31 d0 90 09 12 00 03 09 28 90 01 03 0a 07 09 18 5d 17 d6 28 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}