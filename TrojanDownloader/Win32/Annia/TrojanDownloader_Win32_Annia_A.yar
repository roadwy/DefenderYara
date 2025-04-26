
rule TrojanDownloader_Win32_Annia_A{
	meta:
		description = "TrojanDownloader:Win32/Annia.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {be 82 23 00 00 68 ?? ?? 40 00 ff 15 90 20 59 22 da 2d 4e 75 f2 } //1
		$a_01_1 = {75 67 67 63 3a 2f 2f 34 36 2e 31 34 38 2e 31 39 2e 37 34 2f 6e 69 2e 72 6b 72 } //1 uggc://46.148.19.74/ni.rkr
		$a_03_2 = {53 53 6a 03 53 6a 03 53 68 ?? ?? 40 00 c7 45 64 ?? ?? 40 00 c7 45 68 ?? ?? 40 00 c7 45 6c ?? ?? 40 00 89 5d 70 ff 15 90 20 bb a0 ae 1d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Annia_A_2{
	meta:
		description = "TrojanDownloader:Win32/Annia.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 07 04 0d eb 6e 8a 07 3c 4d 7f 1c 0f be c0 50 e8 ?? ?? ?? ?? 59 85 c0 74 0e 0f be 07 50 e8 ?? ?? ?? ?? 59 85 c0 75 d8 8a 07 3c 6e } //1
		$a_03_1 = {75 67 67 63 3a 2f 2f [0-10] 2f 6e 69 2e 72 6b 72 } //1
		$a_01_2 = {76 6d 77 61 72 65 00 00 76 69 72 74 75 61 6c 00 71 65 6d 75 00 00 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1
		$a_01_3 = {4a 65 76 67 72 53 76 79 72 } //1 JevgrSvyr
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}