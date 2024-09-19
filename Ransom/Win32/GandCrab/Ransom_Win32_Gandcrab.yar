
rule Ransom_Win32_GandCrab{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ff 9c 19 00 00 7d 04 6a 00 ff d6 e8 ?? fa ff ff 8b 4c 24 0c 30 04 39 83 ef 01 79 e3 ff 15 90 90 c7 41 00 64 8b 0d 2c 00 00 00 8b 11 5f 5e c7 42 04 01 00 00 00 33 c0 5b 8b e5 5d c2 10 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Ransom_Win32_GandCrab_2{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {e8 a7 ff ff ff 30 04 37 6a 00 ff 15 ?? ?? 41 00 8d 85 fc f7 ff ff 50 6a 00 ff 15 ?? ?? 41 00 46 3b 75 08 7c cd 90 09 0e 00 6a 00 ff 15 ?? ?? 41 00 ff 15 ?? ?? 41 00 } //1
		$a_02_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? 41 00 c1 e8 10 25 ff 7f 00 00 c3 90 09 05 00 a1 ?? ?? 41 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Ransom_Win32_GandCrab_3{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 45 08 8d 34 07 e8 7d ff ff ff 30 06 47 3b 7d 0c 7c ed } //1
		$a_02_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? 41 00 3d fe 44 05 00 75 1f 8d 85 fc fb ff ff 50 ff 15 ?? ?? 41 00 6a 00 68 ?? ?? 41 00 68 ?? ?? 41 00 ff 15 ?? ?? 41 00 0f b7 05 ?? ?? 41 00 8b 4d fc 33 cd 25 ff 7f 00 00 90 09 05 00 a1 ?? ?? 41 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Ransom_Win32_GandCrab_4{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 4f 02 8d 7f 04 8a d1 8a c1 80 e1 f0 c0 e0 06 0a 47 fd 80 e2 fc c0 e1 02 0a 4f fb c0 e2 04 0a 57 fc 88 0c 1e 88 54 1e 01 88 44 1e 02 83 c6 03 83 6d f8 01 75 ca } //1
		$a_02_1 = {81 fe 37 0e 00 00 7d 14 6a 00 6a 00 6a 00 6a 00 ff d7 6a 00 6a 00 ff 15 ?? ?? 41 00 0f be 1c 1e e8 7b ff ff ff 32 c3 8b 5d fc 88 04 1e 46 3b 75 f8 7c cd } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Ransom_Win32_GandCrab_5{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 00 2d 00 2d 00 42 00 45 00 47 00 49 00 4e 00 20 00 47 00 41 00 4e 00 44 00 43 00 52 00 41 00 42 00 20 00 4b 00 45 00 59 00 2d 00 2d 00 2d 00 } //1 ---BEGIN GANDCRAB KEY---
		$a_01_1 = {69 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 68 00 61 00 76 00 65 00 20 00 74 00 68 00 65 00 20 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 } //1 important files are encrypted and have the extension
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}