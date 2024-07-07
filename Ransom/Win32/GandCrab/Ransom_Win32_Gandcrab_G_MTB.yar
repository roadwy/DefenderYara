
rule Ransom_Win32_Gandcrab_G_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 8b 38 8a 44 0f 03 8a d8 80 e3 90 01 01 c0 e3 04 0a 5c 0f 01 88 5d ff 8a d8 24 90 01 01 c0 e0 02 0a 04 0f c0 e3 06 0a 5c 0f 02 88 04 16 8a 45 ff 46 88 04 16 8b 45 0c 46 88 1c 16 83 c1 04 46 3b 08 72 c3 5f 90 00 } //1
		$a_03_1 = {8b 44 24 14 8d 90 01 02 e8 90 01 02 ff ff 30 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_Gandcrab_G_MTB_2{
	meta:
		description = "Ransom:Win32/Gandcrab.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {01 4c cd 21 54 68 69 73 20 90 19 01 01 70 90 19 01 01 72 90 19 01 01 6f 90 19 01 01 67 90 19 01 01 72 90 19 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 90 00 } //1
		$a_02_1 = {8b f9 85 db 7e 37 8d 49 00 ff 15 90 01 04 ff 15 90 01 04 e8 90 01 04 30 84 37 00 fe ff ff 6a 00 ff 15 90 01 04 8d 85 90 01 04 50 6a 00 ff 15 90 01 04 46 3b f3 7c cc 90 00 } //1
		$a_00_2 = {8d 45 0c 50 6a 00 ff d7 8b 4d 08 a0 3e f4 b7 03 30 04 0e 46 3b f3 7c 92 5f 5e 5b 8b e5 5d c2 08 00 } //1
		$a_02_3 = {cc 6a 00 ff 15 90 01 04 a1 90 01 04 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 01 04 c1 e8 10 25 ff 7f 00 00 c3 90 00 } //1
		$a_00_4 = {6a 00 6a 00 ff d7 69 05 3c f4 b7 03 fd 43 03 00 6a 00 6a 00 05 c3 9e 26 00 a3 3c f4 b7 03 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=2
 
}