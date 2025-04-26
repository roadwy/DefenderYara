
rule Trojan_BAT_AgentTesla_ASFJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {07 8e 69 5d 13 05 07 11 05 91 13 06 08 11 04 1f 16 5d } //1
		$a_01_1 = {d2 13 07 07 11 04 17 58 07 8e 69 5d 91 13 08 } //1
		$a_01_2 = {11 06 11 07 61 11 08 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 09 } //1
		$a_01_3 = {42 61 6e 6b 69 6e 67 53 79 73 74 65 6d 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 BankingSystemSimulation.Properties.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}