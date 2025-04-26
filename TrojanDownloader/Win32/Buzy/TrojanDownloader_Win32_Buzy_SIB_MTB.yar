
rule TrojanDownloader_Win32_Buzy_SIB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Buzy.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 34 42 36 36 39 45 31 2d 43 44 44 34 2d 32 32 30 38 2d 37 41 34 32 2d 41 30 34 35 46 34 36 30 39 37 31 30 } //1 D4B669E1-CDD4-2208-7A42-A045F4609710
		$a_03_1 = {33 ff 8b 48 ?? 83 c8 ?? 85 f6 7e ?? 40 3b c1 7e ?? 33 c0 8a 54 05 ?? 30 94 3d ?? ?? ?? ?? 47 3b fe 7c ?? ff 75 ?? 8d 85 90 1b 05 56 8b 35 ?? ?? ?? ?? 6a ?? 50 ff d6 33 ff 83 c4 10 39 7d ?? 7e ?? ff 35 ?? ?? ?? ?? 8d 85 90 1b 05 68 ?? ?? ?? ?? 6a ?? 50 ff d3 ff 75 90 1b 07 8b f8 8d 85 90 1b 05 57 6a ?? 50 ff d6 83 c4 20 85 ff 7f } //1
		$a_03_2 = {8b fa 83 c7 ?? 3b fb 7e ?? ff d6 6a ?? 99 59 f7 f9 83 c2 30 83 fa 39 7e ?? 83 fa 41 7c ?? 88 54 1d ?? 43 3b df 7c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}