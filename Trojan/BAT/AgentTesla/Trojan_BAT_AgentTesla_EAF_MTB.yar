
rule Trojan_BAT_AgentTesla_EAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 10 07 08 09 93 66 d1 6f ?? 00 00 0a 26 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d e4 } //1
		$a_03_1 = {16 fe 01 2b 01 16 0b 07 2c 10 02 17 9a 28 ?? 00 00 0a 28 ?? 00 00 06 0a 2b 03 1f 28 0a 06 0c 08 2a } //1
		$a_01_2 = {41 70 70 65 6e 64 } //1 Append
		$a_01_3 = {53 70 6c 69 74 } //1 Split
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}