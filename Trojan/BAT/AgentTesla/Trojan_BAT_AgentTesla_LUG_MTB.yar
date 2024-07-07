
rule Trojan_BAT_AgentTesla_LUG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff 90 01 06 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 0b 07 0a 2b 00 06 2a 90 00 } //1
		$a_03_1 = {0a 13 04 11 04 28 90 01 03 06 28 90 01 03 0a 13 05 07 11 05 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 06 11 06 2d cc 90 00 } //1
		$a_01_2 = {64 00 65 00 5f 00 5f 00 5f 00 5f 00 71 00 5f 00 5f 00 5f 00 77 00 61 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f } //1
		$a_01_3 = {71 00 5f 00 4c 00 62 00 5f 00 b3 00 5f 00 97 00 70 00 5f 00 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}