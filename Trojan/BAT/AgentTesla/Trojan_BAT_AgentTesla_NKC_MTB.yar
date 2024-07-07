
rule Trojan_BAT_AgentTesla_NKC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {09 1f 0f 08 1b 5d 59 1e 59 1f 1f 5f 63 5f 0d 06 09 d2 6f 6c 00 00 0a 08 1e 58 0c 08 02 6f 1e 00 00 0a 1b 5a fe 04 13 06 11 06 3a 60 ff ff ff } //1
		$a_03_1 = {06 07 08 1b 5b 93 28 90 01 03 0a 1f 0a 62 0d 08 1b 5b 17 58 07 8e 69 fe 04 13 04 11 04 2c 1b 09 20 90 01 04 28 2c 00 00 06 07 08 1b 5b 17 58 93 28 90 01 03 0a 1b 62 60 0d 08 1b 5b 18 58 07 8e 69 fe 04 13 05 11 05 2c 19 90 00 } //1
		$a_01_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_3 = {49 6e 64 65 78 4f 66 } //1 IndexOf
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_6 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}