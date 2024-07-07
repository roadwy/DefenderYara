
rule TrojanDownloader_Win32_Zlob_ANT{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 32 54 24 24 88 10 48 ff 4c 24 10 75 f0 } //1
		$a_01_1 = {33 7c 24 10 c1 ef 02 47 81 fd a0 71 8e 00 89 7c 24 10 75 } //1
		$a_03_2 = {33 f7 c1 ee 02 46 90 03 02 01 81 fb 3d a0 71 8e 00 8b fe 75 90 00 } //1
		$a_00_3 = {00 67 65 6f 72 67 69 61 20 6d 64 00 } //1 最潥杲慩洠d
		$a_00_4 = {00 7a 65 72 67 00 } //1 稀牥g
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}