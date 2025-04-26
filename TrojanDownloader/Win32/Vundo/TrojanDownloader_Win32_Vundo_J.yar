
rule TrojanDownloader_Win32_Vundo_J{
	meta:
		description = "TrojanDownloader:Win32/Vundo.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 fa 8b 74 05 80 fa 55 75 90 04 01 01 11 } //1
		$a_03_1 = {2b d9 0f b6 1b 0f b6 d2 2b d3 83 fa 12 74 90 04 01 01 3b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Vundo_J_2{
	meta:
		description = "TrojanDownloader:Win32/Vundo.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {81 38 21 43 46 47 } //1
		$a_01_1 = {81 7c 11 fd 0d 0a 0d 0a } //1
		$a_01_2 = {81 3e 77 77 77 2e } //1
		$a_01_3 = {c7 07 68 74 74 70 c7 47 04 3a 2f 2f 00 } //1
		$a_01_4 = {81 fa 47 45 54 20 75 04 33 d2 eb 0b 81 fa 50 4f 53 54 75 b7 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}