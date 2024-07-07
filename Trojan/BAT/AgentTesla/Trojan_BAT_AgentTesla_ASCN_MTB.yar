
rule Trojan_BAT_AgentTesla_ASCN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 8e 69 17 da 13 1e 16 13 1f 2b 1a 11 06 11 05 11 1f 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 1f 17 d6 13 1f 11 1f 11 1e 31 e0 90 00 } //1
		$a_81_1 = {46 69 6e 61 6c 50 72 6f 6a 65 63 74 2e 52 65 73 6f 75 72 63 65 73 } //1 FinalProject.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}