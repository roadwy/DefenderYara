
rule TrojanDownloader_Win32_Harnig_gen_K{
	meta:
		description = "TrojanDownloader:Win32/Harnig.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 10 33 c0 8a 07 47 50 e8 ?? ff ff ff 88 04 1e 46 3b 74 24 18 7c eb 80 24 1e 00 } //1
		$a_02_1 = {68 26 80 ac c8 6a 01 e8 ?? ?? ff ff [0-03] (56|68 ?? ?? ??) ?? ff d0 } //1
		$a_02_2 = {68 d6 4b 7f 7f 6a 01 e8 ?? ?? ff ff [0-03] (56|68 ?? ?? ??) ?? ff d0 } //1
		$a_02_3 = {68 26 80 ac c8 ?? e8 ?? ff ff ff 83 c4 14 56 ff d0 eb ?? 6a 0c be } //1
		$a_00_4 = {0f 01 4d f9 8b 45 fb 25 00 00 f0 ff 3d 00 00 c0 ff 75 04 c6 45 ff 01 0f b6 45 ff c9 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=2
 
}