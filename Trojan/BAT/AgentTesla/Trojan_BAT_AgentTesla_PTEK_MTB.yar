
rule Trojan_BAT_AgentTesla_PTEK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 38 01 00 0a 06 6f 39 01 00 0a 13 04 02 0d 11 04 09 16 } //00 00 
	condition:
		any of ($a_*)
 
}