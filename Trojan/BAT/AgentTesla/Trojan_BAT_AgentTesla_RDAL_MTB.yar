
rule Trojan_BAT_AgentTesla_RDAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 44 4e 56 69 65 77 65 72 } //01 00  SDNViewer
		$a_01_1 = {4a 6f 68 6e 20 43 6f 6c 65 6d 61 6e } //01 00  John Coleman
		$a_01_2 = {42 45 54 41 20 32 } //00 00  BETA 2
	condition:
		any of ($a_*)
 
}