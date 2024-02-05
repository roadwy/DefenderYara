
rule TrojanDownloader_Win32_Buzy_SIB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Buzy.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 34 42 36 36 39 45 31 2d 43 44 44 34 2d 32 32 30 38 2d 37 41 34 32 2d 41 30 34 35 46 34 36 30 39 37 31 30 } //01 00 
		$a_03_1 = {33 ff 8b 48 90 01 01 83 c8 90 01 01 85 f6 7e 90 01 01 40 3b c1 7e 90 01 01 33 c0 8a 54 05 90 01 01 30 94 3d 90 01 04 47 3b fe 7c 90 01 01 ff 75 90 01 01 8d 85 90 1b 05 56 8b 35 90 01 04 6a 90 01 01 50 ff d6 33 ff 83 c4 10 39 7d 90 01 01 7e 90 01 01 ff 35 90 01 04 8d 85 90 1b 05 68 90 01 04 6a 90 01 01 50 ff d3 ff 75 90 1b 07 8b f8 8d 85 90 1b 05 57 6a 90 01 01 50 ff d6 83 c4 20 85 ff 7f 90 00 } //01 00 
		$a_03_2 = {8b fa 83 c7 90 01 01 3b fb 7e 90 01 01 ff d6 6a 90 01 01 99 59 f7 f9 83 c2 30 83 fa 39 7e 90 01 01 83 fa 41 7c 90 01 01 88 54 1d 90 01 01 43 3b df 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}