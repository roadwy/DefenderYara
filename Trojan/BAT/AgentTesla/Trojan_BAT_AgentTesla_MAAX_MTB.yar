
rule Trojan_BAT_AgentTesla_MAAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 03 02 7b 90 01 01 00 00 04 8e 69 5d 91 02 7b 90 01 01 00 00 04 03 91 61 d2 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}