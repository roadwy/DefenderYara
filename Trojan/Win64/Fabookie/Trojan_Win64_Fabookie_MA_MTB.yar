
rule Trojan_Win64_Fabookie_MA_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {e9 97 2a 56 b9 0a d6 1c 1e 25 ae 57 de 0a 52 77 fc 40 b3 44 ec 09 38 79 ae 1b 8a 29 d4 5b bc 3f } //2
		$a_01_1 = {0a 3d af 24 3b 70 81 4b df 5e a1 4d 65 18 45 4a 66 6a 01 74 9a 07 fc 19 6d 13 90 6b 3d 1f 0b 52 } //2
		$a_01_2 = {84 11 2e 6d 3f 1c b3 6f 76 62 42 07 dc 41 8d 71 d8 37 26 79 eb 10 84 76 0e 20 67 2a 20 26 34 44 } //2
		$a_01_3 = {2e 76 6d 70 31 } //1 .vmp1
		$a_01_4 = {53 65 74 54 68 72 65 61 64 41 66 66 69 6e 69 74 79 4d 61 73 6b } //1 SetThreadAffinityMask
		$a_01_5 = {57 69 6e 48 74 74 70 53 65 74 4f 70 74 69 6f 6e } //1 WinHttpSetOption
		$a_01_6 = {47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 57 } //1 GetUserObjectInformationW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}