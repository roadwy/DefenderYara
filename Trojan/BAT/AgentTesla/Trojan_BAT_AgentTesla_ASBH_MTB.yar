
rule Trojan_BAT_AgentTesla_ASBH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 09 8e 69 17 da 13 11 16 13 12 2b 1c 11 04 11 12 09 11 12 9a 1f 10 28 90 01 01 00 00 0a 86 6f 90 01 01 00 00 0a 00 11 12 17 d6 13 12 11 12 11 11 31 de 90 00 } //4
		$a_01_1 = {66 00 69 00 6e 00 61 00 6c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 finalProject.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}