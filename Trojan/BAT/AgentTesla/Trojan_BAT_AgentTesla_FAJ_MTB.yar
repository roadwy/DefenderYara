
rule Trojan_BAT_AgentTesla_FAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 90 01 01 00 00 0a 25 11 04 6f 90 01 01 00 00 0a 25 09 72 90 01 01 01 00 70 6f 90 01 01 00 00 0a 74 0d 00 00 1b 6f 90 01 01 00 00 0a 25 09 72 90 01 01 01 00 70 6f 90 01 01 00 00 0a 74 0d 00 00 1b 6f 90 00 } //3
		$a_01_1 = {51 00 75 00 61 00 6e 00 74 00 75 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 Quantum.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}