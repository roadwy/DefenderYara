
rule Trojan_BAT_AgentTesla_EAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 06 07 91 17 62 06 07 91 1d 63 60 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_EAK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 04 2b 17 00 08 11 04 07 11 04 9a 1f 10 28 ?? 00 00 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc } //2
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {43 75 73 74 6f 6d 65 72 73 5f 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Customers_Simulation.Properties.Resources
		$a_01_3 = {53 70 6c 69 74 } //1 Split
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}