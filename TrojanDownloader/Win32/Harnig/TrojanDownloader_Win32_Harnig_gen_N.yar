
rule TrojanDownloader_Win32_Harnig_gen_N{
	meta:
		description = "TrojanDownloader:Win32/Harnig.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {0f 01 4d f9 8b 45 fb 25 00 00 f0 ff 3d 00 00 c0 ff 75 04 c6 45 ff 01 0f b6 45 ff c9 c3 } //01 00 
		$a_03_1 = {89 45 f0 ff 15 90 01 04 ff 75 f0 89 45 f4 ff 15 90 01 04 83 7d f4 02 74 0d ff 45 fc 83 7d fc 02 0f 8c 90 00 } //01 00 
		$a_03_2 = {83 ff 01 75 07 68 90 01 04 eb 90 01 01 83 ff 02 75 07 68 90 01 04 eb 90 01 01 83 ff 03 75 0e 90 00 } //01 00 
		$a_01_3 = {75 6e 69 71 2e 70 68 70 } //01 00 
		$a_01_4 = {25 75 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}