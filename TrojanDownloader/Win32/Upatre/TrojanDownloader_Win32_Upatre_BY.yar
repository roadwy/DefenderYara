
rule TrojanDownloader_Win32_Upatre_BY{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 06 46 3d 64 64 72 65 e0 f6 } //1
		$a_01_1 = {ac 40 48 48 74 0c 40 66 ab 83 c1 01 84 c0 75 f0 } //1
		$a_01_2 = {6a 2f 6a 2f 6a 31 58 66 ab 58 66 ab } //1
		$a_01_3 = {53 ad 33 c3 ab 5b 4b 49 75 f6 } //1
		$a_01_4 = {ab 33 c0 ab e2 fd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}