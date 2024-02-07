
rule Trojan_BAT_AgentTesla_RDI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 02 7b 03 90 01 03 04 02 7b 90 01 04 6f 90 01 04 5d 6f 90 01 04 03 61 d2 2a 90 00 } //01 00 
		$a_01_1 = {4b 00 61 00 6d 00 70 00 66 00 } //00 00  Kampf
	condition:
		any of ($a_*)
 
}