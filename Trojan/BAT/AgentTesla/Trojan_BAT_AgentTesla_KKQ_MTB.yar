
rule Trojan_BAT_AgentTesla_KKQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f 90 01 03 0a 7e 90 01 03 04 07 7e 90 01 03 04 8e 69 5d 91 61 28 90 01 03 0a 6f 90 01 03 0a 26 07 17 58 0b 90 00 } //1
		$a_01_1 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_2 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_00_4 = {d2 6a 98 21 4e 6e 4c 09 aa e4 b2 de e9 9e 58 e4 c2 5f 42 f8 a7 76 7d ce e0 10 14 b1 8a 99 fd 28 d9 e4 b2 8b a5 85 cc a6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}