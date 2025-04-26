
rule TrojanDownloader_Win32_Spycos_J{
	meta:
		description = "TrojanDownloader:Win32/Spycos.J,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {89 45 e0 8b 45 e8 33 45 e0 89 45 e4 8d 45 d4 8b 55 e4 e8 ?? ?? ?? ?? 8b 55 d4 8b 45 ec e8 } //3
		$a_03_1 = {66 3d 16 04 74 20 8d 95 ?? fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 ?? fe ff ff } //2
		$a_01_2 = {83 f8 06 7f 21 0f 84 d0 00 00 00 48 74 3b 48 74 55 48 0f 84 93 00 00 00 83 e8 02 0f 84 aa 00 00 00 e9 e3 00 00 00 } //2
		$a_01_3 = {2e 63 70 6c 0d 0a 45 72 61 73 65 20 22 43 3a 5c } //1
		$a_01_4 = {69 6e 73 74 61 6c 65 72 2e 63 70 6c 00 } //1
		$a_01_5 = {63 70 6c 4d 69 6e 69 2e 63 70 6c 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}