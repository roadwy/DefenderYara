
rule TrojanDownloader_Win32_Dogkild_K{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 4b e1 22 00 (ff 75 08|50) ff 15 ?? ?? ?? ?? 85 c0 74 } //1
		$a_03_1 = {83 c0 04 89 ?? 83 c0 14 89 ?? 66 81 38 0b 01 75 ?? 8b 4c 24 10 05 e0 00 00 00 } //1
		$a_01_2 = {6b 69 6c 6c 64 6c 6c 2e 64 6c 6c 00 } //1
		$a_01_3 = {5c 5c 2e 5c 4b 49 4c 4c 50 53 5f 44 72 76 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}