
rule TrojanDownloader_Win32_Renos_JH{
	meta:
		description = "TrojanDownloader:Win32/Renos.JH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 1a 5b f7 f3 8b 5d 08 8a 44 15 ce 8b 55 f8 88 04 1a 8d 57 ff 3b f2 7d 05 } //01 00 
		$a_01_1 = {8b 30 0f af 37 46 89 30 8b 09 8b 74 24 0c 8b 06 0f b7 4c 8a 02 } //02 00 
		$a_01_2 = {c7 00 35 4e 5a 01 83 23 00 } //02 00 
		$a_01_3 = {61 20 22 2e 2e 5c 25 73 2e 72 61 72 22 20 2a } //01 00  a "..\%s.rar" *
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Renos_JH_2{
	meta:
		description = "TrojanDownloader:Win32/Renos.JH,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 2e 00 20 00 31 00 39 00 38 00 31 00 2d 00 31 00 39 00 39 00 39 00 } //01 00  Copyright (C) Microsoft Corp. 1981-1999
		$a_01_1 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 20 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}