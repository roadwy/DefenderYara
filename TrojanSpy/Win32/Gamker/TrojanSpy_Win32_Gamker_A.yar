
rule TrojanSpy_Win32_Gamker_A{
	meta:
		description = "TrojanSpy:Win32/Gamker.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //1 ollydbg.exe
		$a_01_1 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } //1 :Zone.Identifier
		$a_01_2 = {88 1f 8b 7d ec 88 5d ff 0f b6 5d 0b 88 1f 0f b6 5d 0b 0f b6 7d ff 03 fb 8a 5d fe 81 e7 ff 00 00 00 32 1c 07 fe c1 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=12
 
}
rule TrojanSpy_Win32_Gamker_A_2{
	meta:
		description = "TrojanSpy:Win32/Gamker.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_00_0 = {62 6f 74 69 64 3d 25 73 26 75 73 65 72 6e 61 6d 65 3d 25 73 26 76 65 72 3d } //1 botid=%s&username=%s&ver=
		$a_01_1 = {81 79 fc ba ba ba ab 75 0e 81 3c 0a ba ba ba ab 75 05 b0 01 } //1
		$a_00_2 = {21 64 6f 77 6e 5f 65 78 65 63 20 28 5c 53 2b 29 20 28 5c 53 2b 29 00 } //1
		$a_00_3 = {21 6b 6e 6f 63 6b 5f 74 69 6d 65 20 28 5c 53 2b 29 20 28 5c 53 2b 29 00 } //1
		$a_00_4 = {21 73 79 73 5f 69 6e 69 74 20 28 5c 53 2b 29 3a 28 5c 53 2b 29 20 28 5c 53 2b 29 00 } //1
		$a_00_5 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d } //1 Referer: http://www.facebook.com
		$a_00_6 = {45 78 65 63 43 6d 64 44 65 73 6b 00 } //1 硅捥浃䑤獥k
		$a_00_7 = {41 00 44 00 4d 00 49 00 4e 00 00 00 55 00 53 00 45 00 52 00 00 00 00 00 25 77 73 5c 25 77 73 5c 25 77 73 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=3
 
}
rule TrojanSpy_Win32_Gamker_A_3{
	meta:
		description = "TrojanSpy:Win32/Gamker.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {c6 85 cf fe ff ff 66 c6 85 d0 fe ff ff 74 c6 85 d1 fe ff ff 53 c6 85 d2 fe ff ff 53 c6 85 d3 fe ff ff 35 c6 85 d4 fe ff ff 35 c6 85 d5 fe ff ff 31 c6 85 d6 fe ff ff 31 c6 85 d7 fe ff ff 47 c6 85 d8 fe ff ff 61 c6 85 d9 fe ff ff 74 c6 85 da fe ff ff 65 } //10
		$a_01_1 = {c6 85 d7 fe ff ff 66 c6 85 d8 fe ff ff 74 c6 85 d9 fe ff ff 53 c6 85 da fe ff ff 53 c6 85 db fe ff ff 35 c6 85 dc fe ff ff 35 c6 85 dd fe ff ff 31 c6 85 de fe ff ff 31 c6 85 df fe ff ff 47 c6 85 e0 fe ff ff 61 c6 85 e1 fe ff ff 74 c6 85 e2 fe ff ff 65 } //10
		$a_03_2 = {4d 69 63 72 c7 45 90 01 01 6f 73 6f 66 c7 45 90 01 01 74 53 53 35 c7 45 90 01 01 35 31 31 47 c7 45 90 01 01 61 74 65 00 90 00 } //10
		$a_01_3 = {65 79 75 69 6f 61 00 00 71 77 72 74 70 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d 5f 00 } //1
		$a_01_4 = {33 d2 4f f7 f7 8a 54 15 d4 8b 45 fc 8b 4d 08 88 14 08 80 fa 5f 0f 84 05 ff ff ff 40 89 45 fc 3b 45 0c 0f 8c e8 fd ff ff } //1
		$a_03_5 = {eb 05 8b ff 8b 4d f4 0f b6 0c 31 88 4d fe 8a 88 00 01 00 00 0f b6 f9 0f b6 14 07 03 f8 88 55 0b 8a 90 90 01 01 00 00 02 55 0b 90 00 } //1
		$a_01_6 = {83 f9 18 72 5d 8b 1e 81 fb 41 50 33 32 75 53 8b 5e 04 83 fb 18 72 4b 29 d9 72 47 39 4e 08 77 42 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}