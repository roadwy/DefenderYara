
rule TrojanDownloader_Win64_Dorifel_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Dorifel.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {80 30 5e 80 70 01 5e 48 83 c0 02 48 39 ?? 75 f0 } //2
		$a_01_1 = {89 c2 41 80 34 16 5e 8d 50 01 44 39 fa 73 46 } //2
		$a_01_2 = {80 30 6e 48 83 c0 01 48 39 d0 75 f4 } //2
		$a_01_3 = {80 30 5e 48 83 c0 01 48 39 d0 75 f4 } //2
		$a_01_4 = {83 f2 5e 88 10 83 85 18 02 00 00 01 8b 85 18 02 00 00 3b 85 dc 01 00 00 72 c3 } //2
		$a_01_5 = {44 39 e0 73 09 80 34 07 6e 48 ff c0 eb f2 } //2
		$a_01_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=3
 
}