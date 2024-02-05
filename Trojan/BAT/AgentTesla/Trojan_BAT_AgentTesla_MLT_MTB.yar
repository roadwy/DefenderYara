
rule Trojan_BAT_AgentTesla_MLT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {61 2b a8 28 90 01 04 06 90 01 1e 0b 09 90 01 05 5a 90 01 05 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}