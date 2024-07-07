
rule Trojan_BAT_AgentTesla_CTM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 13 05 11 05 28 90 01 03 0a 23 00 00 00 00 00 80 73 40 59 28 90 01 03 0a b7 13 06 07 11 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 00 11 04 17 d6 13 04 11 04 09 8e 69 fe 04 13 07 11 07 2d 90 00 } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_3 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}