
rule PWS_Win32_Zbot{
	meta:
		description = "PWS:Win32/Zbot,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 11 8b 74 24 38 8b d0 2b f2 8a 10 88 14 06 40 4f 75 f7 8b 01 8b 4c 24 1c 01 44 24 38 83 c1 08 83 39 00 89 4c 24 1c 8d 41 fc 89 4c 24 34 0f 85 1c ff ff ff 8b 44 24 40 6a 00 50 c7 40 01 10 67 41 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule PWS_Win32_Zbot_2{
	meta:
		description = "PWS:Win32/Zbot,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 44 a8 65 00 b9 44 a8 65 00 b9 44 a8 65 00 8b d5 89 15 90 01 03 00 90 00 } //1
		$a_03_1 = {89 8d 34 fd ff ff 8b 15 90 01 04 89 15 90 01 04 8d 85 2c fd ff ff 90 02 ff 68 00 00 00 80 ff 15 90 1b 01 90 00 } //1
		$a_01_2 = {c7 85 98 fd ff ff 95 f3 06 00 c6 85 e7 fd ff ff 8b c6 85 46 fd ff ff 55 c6 85 47 fd ff ff 6a c6 85 97 fd ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule PWS_Win32_Zbot_3{
	meta:
		description = "PWS:Win32/Zbot,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 3a 5c 76 61 77 75 39 6f 67 67 76 2e 70 64 62 } //1 Z:\vawu9oggv.pdb
		$a_01_1 = {73 00 61 00 6c 00 61 00 75 00 62 00 68 00 2e 00 65 00 78 00 65 00 } //1 salaubh.exe
		$a_03_2 = {83 c4 0c a3 cc 67 49 00 8b 45 10 25 ff 00 00 00 88 45 ef 8b 45 0c 03 45 f8 0f b6 00 8b 4d 0c 03 4d f8 0f b6 09 33 c8 8b 45 0c 03 45 f8 88 08 ff 35 cc 67 49 00 ff 75 14 0f b6 45 ee 50 e8 90 01 04 83 c4 0c a3 cc 67 49 00 ff 75 ef ff 75 ee e8 90 01 04 59 59 0f b6 c0 8b 4d 0c 03 4d f8 0f b6 09 03 c8 8b 45 0c 03 45 f8 88 08 ff 35 cc 67 49 00 0f b6 45 ef 50 0f b6 45 ee 50 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule PWS_Win32_Zbot_4{
	meta:
		description = "PWS:Win32/Zbot,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 42 4f 54 49 44 25 00 25 42 4f 54 4e 45 54 25 00 00 00 00 25 42 43 2d 2a 2d 2a 2d 2a 2d 2a 25 00 00 00 00 25 56 49 44 45 4f 25 00 48 54 54 50 } //1
		$a_01_1 = {68 76 6e 63 5f 6d 6f 64 75 6c 65 00 63 69 74 5f 68 76 6e 63 2e 6d 6f 64 75 6c 65 00 63 6f 6f 6b 69 65 5f 6d 6f 64 75 6c 65 00 00 00 63 69 74 5f 66 66 63 6f 6f 6b 69 65 2e 6d 6f 64 75 6c 65 00 76 69 64 65 6f 5f 6d 6f 64 75 6c 65 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}