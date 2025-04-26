
rule Trojan_Win32_Qbot_RMA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b a5 08 00 c7 05 } //1
		$a_03_1 = {89 10 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {52 64 72 66 76 74 4b 6a 68 67 62 79 } //RdrfvtKjhgby  1
		$a_80_1 = {4f 6a 68 6e 62 67 57 64 63 74 66 76 67 79 62 } //OjhnbgWdctfvgyb  1
		$a_80_2 = {53 64 72 63 66 74 76 4d 6e 68 67 62 79 } //SdrcftvMnhgby  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Qbot_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {4a 67 4e 6e 58 47 64 68 } //JgNnXGdh  1
		$a_80_1 = {69 71 64 6f 65 45 59 4f 48 65 } //iqdoeEYOHe  1
		$a_80_2 = {69 73 78 46 42 44 } //isxFBD  1
		$a_80_3 = {73 75 45 4f 71 6a 57 } //suEOqjW  1
		$a_80_4 = {77 44 46 6b 76 } //wDFkv  1
		$a_80_5 = {7a 45 58 61 75 4f 66 70 } //zEXauOfp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Qbot_RMA_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 02 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RMA_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 ?? 03 d8 68 8c 12 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 8c 12 00 00 6a } //1
		$a_02_1 = {03 d8 68 8c 12 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 31 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 ?? ?? ?? ?? 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_RMA_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  1
		$a_80_1 = {45 6b 50 55 48 79 69 79 42 4b } //EkPUHyiyBK  1
		$a_80_2 = {49 79 47 62 5a 6b 4a 55 } //IyGbZkJU  1
		$a_80_3 = {5a 7a 71 64 4e 7a 6b 67 79 68 } //ZzqdNzkgyh  1
		$a_80_4 = {76 52 53 66 4b 6b 7a 6a 68 } //vRSfKkzjh  1
		$a_80_5 = {6d 59 4f 79 51 52 } //mYOyQR  1
		$a_80_6 = {79 4a 74 75 48 45 74 65 69 } //yJtuHEtei  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}