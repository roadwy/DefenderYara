
rule Trojan_BAT_AgentTesla_MLQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {17 9a 0b 02 07 28 90 02 05 16 28 90 02 05 16 90 09 16 00 28 90 01 0e 0a 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}