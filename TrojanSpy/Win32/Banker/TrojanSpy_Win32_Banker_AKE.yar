
rule TrojanSpy_Win32_Banker_AKE{
	meta:
		description = "TrojanSpy:Win32/Banker.AKE,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {8b d8 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 b8 ?? ?? ?? ?? 0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 } //3
		$a_03_1 = {89 45 e8 3b 75 f4 7d 03 46 eb 05 be 01 00 00 00 b8 ?? ?? ?? ?? 33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 } //3
		$a_01_2 = {89 43 04 c6 43 08 b8 8b 45 08 89 43 09 66 c7 43 0d ff e0 } //1
		$a_03_3 = {07 41 72 71 75 69 76 6f 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 45 64 69 74 61 72 04 } //1
		$a_03_4 = {06 45 78 69 62 69 72 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 09 46 61 76 6f 72 69 74 6f 73 04 } //1
		$a_03_5 = {0b 46 65 72 72 61 6d 65 6e 74 61 73 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 41 6a 75 64 61 04 } //1
		$a_01_6 = {10 01 53 65 6e 64 4d 61 69 6c 5f 46 6f 72 5f 45 77 62 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}