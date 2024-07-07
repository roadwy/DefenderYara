
rule TrojanDownloader_Win32_Delf_LT{
	meta:
		description = "TrojanDownloader:Win32/Delf.LT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 65 6d 70 31 25 64 2e 74 78 74 } //1 temp1%d.txt
		$a_01_1 = {7b 39 46 43 35 37 37 39 44 2d 33 42 35 38 2d 34 44 35 46 2d 42 41 32 41 2d 39 42 41 43 36 34 45 43 34 36 41 45 7d } //1 {9FC5779D-3B58-4D5F-BA2A-9BAC64EC46AE}
		$a_03_2 = {74 65 73 74 2e 35 32 63 6f 6d 6e 65 74 63 6e 2e 63 6f 6d 90 01 09 68 74 74 70 3a 2f 2f 25 73 2f 74 6f 6f 6c 73 2e 74 78 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Delf_LT_2{
	meta:
		description = "TrojanDownloader:Win32/Delf.LT,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 32 31 31 2e 33 33 2e 31 32 33 2e 34 30 2f 74 64 6f 78 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6d 61 63 3d 25 73 26 70 61 72 74 6e 65 72 3d 25 73 } //1 http://211.33.123.40/tdox/install.php?mac=%s&partner=%s
		$a_01_1 = {16 00 00 00 53 6f 66 74 77 61 72 65 5c 69 63 6f 6e 20 61 63 74 69 76 65 78 78 00 00 ff ff ff ff } //1
		$a_01_2 = {8b 45 ec c1 e0 06 03 d8 89 5d ec 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d ec d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 ec 5a 8b ca 99 f7 f9 89 55 ec 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}