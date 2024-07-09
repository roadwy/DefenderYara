
rule TrojanDownloader_Win32_Conhook_AF{
	meta:
		description = "TrojanDownloader:Win32/Conhook.AF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 00 25 73 3f 61 3d 25 73 26 74 3d 25 73 26 66 3d 25 69 00 } //1 䕇T猥愿┽♳㵴猥昦┽i
		$a_01_1 = {25 73 5f 5f 63 30 30 25 58 2e 25 73 00 } //1
		$a_03_2 = {8a 01 3c 30 7c 11 3c 7a 7f 0d 3c 61 0f be c0 7c 03 83 e8 20 88 06 46 41 ff 4d f8 75 e3 ff 75 f4 ff 15 ?? ?? ?? 10 8d 45 fc } //1
		$a_03_3 = {83 65 fc 00 68 ?? ?? 00 10 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 85 c0 75 02 c9 c3 8d 4d fc 51 6a 00 6a 01 6a 14 ff d0 } //1
		$a_03_4 = {74 29 68 f4 01 00 00 ff d6 55 57 e8 ?? ?? ff ff 85 c0 74 0c 53 ff d6 e8 ?? ?? 00 00 84 c0 75 1d 83 7c 24 10 03 77 09 ff 44 24 10 53 ff d6 eb c1 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2) >=3
 
}