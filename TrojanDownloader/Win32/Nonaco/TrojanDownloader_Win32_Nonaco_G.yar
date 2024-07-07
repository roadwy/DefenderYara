
rule TrojanDownloader_Win32_Nonaco_G{
	meta:
		description = "TrojanDownloader:Win32/Nonaco.G,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {69 53 65 63 75 72 69 74 79 2e 64 6c 6c } //1 iSecurity.dll
		$a_00_1 = {77 73 63 75 69 2e 63 70 6c } //1 wscui.cpl
		$a_00_2 = {70 72 6f 6d 6f 2e 73 32 66 6e 65 77 2e 63 6f 6d } //1 promo.s2fnew.com
		$a_00_3 = {41 38 33 31 31 45 38 46 2d 45 34 35 39 2d 34 44 32 32 2d 38 39 42 34 2d 43 42 39 44 43 46 31 30 41 34 32 35 } //1 A8311E8F-E459-4D22-89B4-CB9DCF10A425
		$a_80_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_00_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule TrojanDownloader_Win32_Nonaco_G_2{
	meta:
		description = "TrojanDownloader:Win32/Nonaco.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_03_0 = {85 c0 74 12 68 90 01 04 50 ff 15 90 01 04 85 c0 74 02 ff e0 90 00 } //1
		$a_01_1 = {69 53 65 63 75 72 69 74 79 2e 63 70 6c 00 00 00 76 25 73 5c 00 00 00 00 5c 69 53 65 63 75 72 69 } //2
		$a_01_2 = {c6 45 ff 01 6a 07 ff 75 0c ff d7 5f 5e 8a 45 ff 5b c9 c3 } //1
		$a_01_3 = {45 58 45 00 72 75 6e 64 6c 6c 33 32 20 22 25 73 22 2c 53 65 63 75 72 69 74 79 4d 6f 6e 69 74 6f 72 00 } //2 塅E畲摮汬㈳∠猥Ⱒ敓畣楲祴潍楮潴r
		$a_01_4 = {8d 78 0d 8d 04 0f bb ff 00 00 00 99 f7 fb 32 55 0f 88 16 8a 41 01 46 41 84 c0 88 45 0f 75 e4 } //1
		$a_01_5 = {69 53 65 63 75 72 69 74 79 2e 63 70 6c 2c 53 65 63 75 72 69 74 79 4d 6f 6e 69 74 6f 72 00 } //1
		$a_01_6 = {72 65 63 6f 6d 6d 65 64 65 64 20 74 6f 20 69 6e 73 74 61 6c 6c 20 61 6e 74 69 } //1 recommeded to install anti
		$a_01_7 = {72 00 75 00 6e 00 2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 00 00 65 00 78 00 65 00 2d 00 75 00 72 00 6c 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}