
rule Trojan_BAT_AgentTesla_RDAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 44 4e 56 69 65 77 65 72 } //1 SDNViewer
		$a_01_1 = {4a 6f 68 6e 20 43 6f 6c 65 6d 61 6e } //1 John Coleman
		$a_01_2 = {42 45 54 41 20 32 } //1 BETA 2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}