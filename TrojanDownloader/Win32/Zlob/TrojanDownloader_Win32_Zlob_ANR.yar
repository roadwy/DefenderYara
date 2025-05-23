
rule TrojanDownloader_Win32_Zlob_ANR{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_03_0 = {01 00 00 47 90 09 04 00 c6 84 24 } //3
		$a_03_1 = {01 00 00 45 90 09 04 00 c6 84 24 } //3
		$a_03_2 = {01 00 00 54 90 09 04 00 c6 84 24 } //3
		$a_01_3 = {00 67 65 6f 72 67 69 61 20 6d 64 00 } //1 最潥杲慩洠d
		$a_03_4 = {c1 ee 02 46 3d 90 17 02 03 03 40 36 8e c0 fd 8c 00 89 74 24 ?? 75 } //1
		$a_03_5 = {00 64 75 6d 62 [0-04] 25 64 [0-04] 6d 69 73 73 69 6e 67 77 6f 72 6c 64 00 } //1
		$a_01_6 = {00 77 65 77 74 25 64 2e 62 61 74 00 } //1
		$a_03_7 = {5c 4d 6d 51 54 5f 76 [0-07] 5f 73 76 6e 5c 41 64 62 44 65 76 69 63 65 4a 6f 62 54 68 72 65 61 64 2e 63 70 70 } //-14
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*-14) >=10
 
}