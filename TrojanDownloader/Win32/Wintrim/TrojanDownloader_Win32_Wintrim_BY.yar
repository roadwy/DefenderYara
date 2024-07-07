
rule TrojanDownloader_Win32_Wintrim_BY{
	meta:
		description = "TrojanDownloader:Win32/Wintrim.BY,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_03_0 = {88 0a 8b 45 08 03 85 90 01 02 ff ff 8b 8d 90 01 02 ff ff 8a 10 32 94 0d 90 01 02 ff ff 8b 45 08 03 85 90 01 02 ff ff 88 10 8b 4d 08 03 8d 90 01 02 ff ff 8b 95 90 01 02 ff ff 8a 01 32 84 15 90 01 02 ff ff 8b 4d 08 03 8d 90 01 02 ff ff 88 01 e9 9f fe ff ff 90 00 } //2
		$a_03_1 = {3b 55 ac 0f 83 07 01 00 00 8b 85 90 01 02 ff ff 25 ff 00 00 00 39 85 90 01 02 ff ff 75 0a 90 00 } //2
		$a_03_2 = {83 78 28 00 74 1b 8b 8d 90 01 02 ff ff 8b 95 90 01 02 ff ff 03 51 28 89 95 d8 f7 ff ff ff 95 d8 f7 ff ff 68 0f 00 01 00 ff 55 90 01 01 b8 0f 00 01 00 90 00 } //2
		$a_03_3 = {66 8b 11 81 fa 4d 5a 00 00 74 12 68 04 00 01 00 ff 55 90 01 01 b8 04 00 01 00 e9 90 01 01 0e 00 00 90 00 } //1
		$a_03_4 = {83 fa 43 0f 85 90 01 01 00 00 00 8b 45 f0 0f be 48 01 83 f9 3a 0f 85 90 01 01 00 00 00 8b 55 f0 0f be 42 02 83 f8 5c 75 7c 8b 4d f0 0f be 51 03 83 fa 6d 75 70 90 00 } //1
		$a_01_5 = {c6 45 d4 25 c6 45 d5 30 c6 45 d6 38 c6 45 d7 58 c6 45 d8 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}