
rule Trojan_BAT_AgentTesla_ASFP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 11 0b 28 ?? 00 00 06 13 0d 07 11 09 17 58 09 5d 91 13 0e } //1
		$a_01_1 = {ff 11 09 11 04 5d 13 0b 11 } //1
		$a_01_2 = {07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 11 } //1
		$a_01_3 = {51 75 61 6e 74 75 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Quantum.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}