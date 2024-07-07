
rule Trojan_BAT_AgentTesla_MBKF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 28 90 01 01 00 00 06 1f 10 28 90 01 01 00 00 06 d2 9c 11 05 90 00 } //1
		$a_01_1 = {62 32 32 36 2d 65 64 65 65 34 34 38 39 62 34 38 38 } //1 b226-edee4489b488
		$a_01_2 = {44 4c 50 4b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } //1 DLPK.Properties.Resource
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}