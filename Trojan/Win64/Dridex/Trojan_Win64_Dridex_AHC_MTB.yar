
rule Trojan_Win64_Dridex_AHC_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6e 6e 78 6a 32 75 71 31 } //nnxj2uq1  3
		$a_80_1 = {43 3a 5c 70 6f 69 6e 74 65 72 73 2e 74 78 74 } //C:\pointers.txt  3
		$a_80_2 = {53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //System32\drivers\etc\hosts  3
		$a_80_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntivirusProduct  3
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 41 70 70 65 6e 64 41 73 79 6e 63 } //DownloadAppendAsync  3
		$a_80_5 = {51 32 68 70 62 47 74 68 64 45 68 30 62 57 78 55 62 31 68 74 62 41 3d 3d } //Q2hpbGthdEh0bWxUb1htbA==  3
		$a_80_6 = {51 32 68 70 62 47 74 68 64 46 4e 76 59 32 74 6c 64 41 3d 3d } //Q2hpbGthdFNvY2tldA==  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}