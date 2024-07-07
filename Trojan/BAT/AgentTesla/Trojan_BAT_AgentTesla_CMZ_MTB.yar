
rule Trojan_BAT_AgentTesla_CMZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 18 d8 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a b4 9c 11 04 17 d6 13 04 90 00 } //1
		$a_01_1 = {57 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 57 } //1 W__________W
		$a_01_2 = {58 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 58 } //1 X__________X
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}