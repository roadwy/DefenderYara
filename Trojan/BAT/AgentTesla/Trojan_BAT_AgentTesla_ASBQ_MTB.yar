
rule Trojan_BAT_AgentTesla_ASBQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 05 8e 69 17 da 13 1f 16 13 20 2b 1b 11 06 11 05 11 20 9a 1f 10 28 90 01 01 01 00 0a b4 6f 90 01 01 01 00 0a 00 11 20 17 d6 13 20 11 20 11 1f 31 df 90 00 } //4
		$a_01_1 = {46 00 69 00 6e 00 61 00 6c 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Final_Project.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}