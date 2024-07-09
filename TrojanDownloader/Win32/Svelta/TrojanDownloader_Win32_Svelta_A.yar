
rule TrojanDownloader_Win32_Svelta_A{
	meta:
		description = "TrojanDownloader:Win32/Svelta.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 7c 24 40 00 75 1c 8b c6 38 9c 24 d2 00 00 00 75 07 68 ?? ?? ?? 00 eb 05 } //1
		$a_03_1 = {73 74 61 74 75 73 65 73 2f 75 73 65 72 5f 74 69 6d 65 6c 69 6e 65 2f [0-0a] 2e 72 73 73 } //1
		$a_01_2 = {2e 70 68 70 3f 75 73 65 72 3d 25 73 26 6e 61 6d 65 3d 25 73 26 77 69 6e 76 65 72 3d 25 73 26 4d 41 43 3d } //1 .php?user=%s&name=%s&winver=%s&MAC=
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}