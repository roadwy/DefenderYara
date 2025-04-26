
rule Trojan_BAT_AgentTesla_NTW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {fb da 81 27 6e df fa d5 e4 59 8e 32 6d 44 76 51 38 ba cc 51 a4 e3 74 60 aa c6 ef 6e a5 37 a4 57 6f bf 0b c9 0e c8 95 de d3 fa 47 1c 71 3b d7 7e 4d } //1
		$a_01_1 = {33 31 34 43 46 30 42 34 39 45 35 41 } //1 314CF0B49E5A
		$a_81_2 = {46 6f 72 74 2e 64 6c 6c } //1 Fort.dll
		$a_81_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_4 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_5 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
		$a_01_6 = {54 6f 41 72 67 62 } //1 ToArgb
		$a_01_7 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}