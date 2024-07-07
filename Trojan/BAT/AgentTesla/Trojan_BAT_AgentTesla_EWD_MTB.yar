
rule Trojan_BAT_AgentTesla_EWD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 11 06 17 da 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 09 11 06 09 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 06 da 13 07 11 04 11 07 28 90 01 03 06 28 90 01 03 0a 28 90 01 03 0a 13 04 11 06 17 d6 13 06 90 00 } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_2 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}