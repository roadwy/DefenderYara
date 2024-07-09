
rule TrojanDownloader_Win32_Bagle_ACB{
	meta:
		description = "TrojanDownloader:Win32/Bagle.ACB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 3e 31 75 ?? 56 8b fe 46 eb 01 a4 80 3e 00 75 fa } //1
		$a_03_1 = {74 19 57 53 e8 ?? ?? ?? ?? 0b c0 75 07 5f 5e 5b c9 c2 08 00 89 06 83 c6 04 eb da } //1
		$a_03_2 = {3d 41 56 41 53 75 ?? 66 a1 ?? ?? ?? ?? 66 83 e0 df 66 3d 54 21 } //1
		$a_01_3 = {53 31 6f 31 66 31 74 31 77 31 61 31 72 31 65 31 } //1 S1o1f1t1w1a1r1e1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}