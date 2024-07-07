
rule TrojanDownloader_Win32_Upatre_BM{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ac 3c 39 77 0c 3c 2e 72 08 fe c0 04 13 66 ab e2 ef } //1
		$a_03_1 = {33 c1 ab ff 45 90 01 01 ff 45 90 01 01 59 49 75 eb 90 00 } //1
		$a_01_2 = {8b c8 fe c1 fe c1 57 fe c1 fe c1 fc ab 49 75 fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}