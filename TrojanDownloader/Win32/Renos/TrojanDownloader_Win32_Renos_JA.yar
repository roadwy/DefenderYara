
rule TrojanDownloader_Win32_Renos_JA{
	meta:
		description = "TrojanDownloader:Win32/Renos.JA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 83 c7 04 83 fb 0a 72 } //2
		$a_03_1 = {83 f9 05 7d 13 8a 94 0d ?? ?? ff ff 81 f2 ?? 00 00 00 88 14 01 41 eb e2 } //2
		$a_03_2 = {6a 0c 50 68 00 14 2d 00 ff 75 ?? ff 15 ?? ?? ?? 00 } //2
		$a_03_3 = {0f be 09 83 f1 ?? 83 f9 42 0f 84 ?? ?? 00 00 83 f9 4f 74 0b 83 f9 55 0f 84 ?? ?? 00 00 } //2
		$a_01_4 = {8a 5a 03 80 fb 3d 0f 85 8a 00 00 00 8a 42 02 3a c3 75 38 } //1
		$a_01_5 = {77 07 3d 00 00 00 80 73 } //1
		$a_03_6 = {68 58 4d 56 c7 85 ?? ?? ff ff 58 56 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}