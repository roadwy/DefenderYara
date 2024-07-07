
rule Trojan_BAT_AgentTesla_LTI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 90 01 03 06 28 90 01 03 0a 13 05 07 11 05 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 06 11 06 2d cc 90 00 } //1
		$a_03_1 = {02 6c 23 ff 90 01 06 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 0b 07 0a 2b 00 06 2a 90 00 } //1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_3 = {42 75 6e 69 66 75 5f 54 } //1 Bunifu_T
		$a_81_4 = {65 78 74 42 6f 78 } //1 extBox
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}