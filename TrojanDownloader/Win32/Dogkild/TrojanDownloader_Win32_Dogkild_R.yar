
rule TrojanDownloader_Win32_Dogkild_R{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {7e 0e fe 8e ?? ?? ?? ?? 57 46 ff d3 3b f0 7c f2 } //1
		$a_03_1 = {68 4b e1 22 00 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 74 0f } //1
		$a_03_2 = {83 ce ff c6 45 ?? 5c c6 45 ?? 5c c6 45 ?? 2e c6 45 ?? 5c c6 45 ?? 6d c6 45 ?? 73 c6 45 ?? 63 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 69 c6 45 ?? 66 c6 45 ?? 67 } //1
		$a_03_3 = {53 50 c6 45 ?? 63 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 66 c6 45 ?? 69 c6 45 ?? 67 c6 45 ?? 20 c6 45 ?? 61 c6 45 ?? 76 c6 45 ?? 70 } //1
		$a_03_4 = {88 45 0b 8d 45 f8 50 8d 45 0b 6a 01 50 ff 75 fc ff 15 ?? ?? ?? ?? ff 75 10 46 57 ff 15 ?? ?? ?? ?? 3b f0 72 d4 } //1
		$a_01_5 = {8b f0 c1 ee 19 c1 e0 07 0b f0 0f be c1 8a 4a 01 33 c6 42 84 c9 75 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}