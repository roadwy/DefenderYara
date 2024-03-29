
rule Trojan_Win32_Qbot_RMA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b a5 08 00 c7 05 } //01 00 
		$a_03_1 = {89 10 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 6a 00 e8 90 01 04 8b d8 a1 90 01 04 83 c0 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 64 72 66 76 74 4b 6a 68 67 62 79 } //RdrfvtKjhgby  01 00 
		$a_80_1 = {4f 6a 68 6e 62 67 57 64 63 74 66 76 67 79 62 } //OjhnbgWdctfvgyb  01 00 
		$a_80_2 = {53 64 72 63 66 74 76 4d 6e 68 67 62 79 } //SdrcftvMnhgby  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {4a 67 4e 6e 58 47 64 68 } //JgNnXGdh  01 00 
		$a_80_1 = {69 71 64 6f 65 45 59 4f 48 65 } //iqdoeEYOHe  01 00 
		$a_80_2 = {69 73 78 46 42 44 } //isxFBD  01 00 
		$a_80_3 = {73 75 45 4f 71 6a 57 } //suEOqjW  01 00 
		$a_80_4 = {77 44 46 6b 76 } //wDFkv  01 00 
		$a_80_5 = {7a 45 58 61 75 4f 66 70 } //zEXauOfp  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RMA_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {01 02 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RMA_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 90 01 01 03 d8 68 8c 12 00 00 6a 00 e8 90 01 04 03 d8 68 8c 12 00 00 6a 90 00 } //01 00 
		$a_02_1 = {03 d8 68 8c 12 00 00 6a 00 e8 90 01 04 03 d8 a1 90 01 04 31 18 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 83 45 90 01 01 04 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RMA_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  01 00 
		$a_80_1 = {45 6b 50 55 48 79 69 79 42 4b } //EkPUHyiyBK  01 00 
		$a_80_2 = {49 79 47 62 5a 6b 4a 55 } //IyGbZkJU  01 00 
		$a_80_3 = {5a 7a 71 64 4e 7a 6b 67 79 68 } //ZzqdNzkgyh  01 00 
		$a_80_4 = {76 52 53 66 4b 6b 7a 6a 68 } //vRSfKkzjh  01 00 
		$a_80_5 = {6d 59 4f 79 51 52 } //mYOyQR  01 00 
		$a_80_6 = {79 4a 74 75 48 45 74 65 69 } //yJtuHEtei  00 00 
	condition:
		any of ($a_*)
 
}