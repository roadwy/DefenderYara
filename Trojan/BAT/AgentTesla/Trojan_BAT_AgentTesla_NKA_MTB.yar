
rule Trojan_BAT_AgentTesla_NKA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {70 07 08 1b 5b 93 28 90 01 03 0a 1f 0a 62 0d 08 1b 5b 17 58 07 8e 69 fe 04 13 04 11 04 2c 16 90 00 } //1
		$a_01_1 = {09 1f 0f 08 1b 5d 59 1e 59 1f 1f 5f 63 5f 0d 06 09 d2 6f b2 00 00 0a 00 00 08 1e 58 0c 08 02 6f 2b 00 00 0a 1b 5a fe 04 13 06 11 06 3a 6c ff ff ff } //1
		$a_01_2 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //1
		$a_01_3 = {00 42 61 72 62 61 72 61 00 } //1
		$a_01_4 = {00 50 72 69 65 6e 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}