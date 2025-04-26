
rule Backdoor_BAT_Crysan_ABU_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {02 11 08 95 06 11 08 1f 0f 5f 95 61 13 09 06 11 08 1f 0f 5f 06 11 08 1f 0f 5f 95 11 09 61 20 19 ?? ?? 3d 58 9e 09 11 04 11 09 d2 9c 09 11 04 } //3
		$a_03_1 = {08 16 1a 28 2d ?? ?? 0a 08 16 28 2e ?? ?? 0a 13 04 11 04 8d 18 ?? ?? 01 25 17 73 2f ?? ?? 0a 13 05 06 6f 27 ?? ?? 0a 1b 6a 59 } //3
		$a_01_2 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_01_3 = {44 65 63 6f 64 65 57 69 74 68 4d 61 74 63 68 42 79 74 65 } //1 DecodeWithMatchByte
		$a_01_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_5 = {44 65 63 6f 64 65 44 69 72 65 63 74 42 69 74 73 } //1 DecodeDirectBits
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}