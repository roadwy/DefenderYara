
rule Trojan_BAT_AgentTesla_ABJP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 41 00 73 00 73 00 61 00 73 00 73 00 69 00 6e 00 2e 00 52 00 65 00 73 00 6f 00 43 00 53 00 } //4 NetworkAssassin.ResoCS
		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 41 00 73 00 73 00 61 00 73 00 73 00 69 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 NetworkAssassin.Properties.Resources
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}