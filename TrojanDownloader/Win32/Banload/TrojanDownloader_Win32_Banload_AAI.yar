
rule TrojanDownloader_Win32_Banload_AAI{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {89 45 e0 c7 45 e8 01 00 00 00 8b 45 f8 8b 55 e8 0f b7 44 50 fe 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 ec 7d 03 46 eb 05 be 01 00 00 00 8b 45 f4 0f b7 44 70 fe 33 d8 8d 45 d0 50 89 5d d4 c6 45 d8 00 8d 55 d4 33 c9 b8 24 e7 40 00 } //1
		$a_00_1 = {39 00 31 00 44 00 39 00 37 00 32 00 44 00 31 00 30 00 37 00 34 00 37 00 38 00 46 00 33 00 32 00 36 00 33 00 38 00 39 00 43 00 38 00 31 00 43 00 34 00 43 00 46 00 31 00 36 00 36 00 } //1 91D972D107478F326389C81C4CF166
		$a_02_2 = {74 72 8b 55 fc 8d 85 a8 fd ff ff e8 ?? ?? ?? ?? ba 01 00 00 00 8d 85 a8 fd ff ff e8 ?? ?? ?? ?? ?? ?? ?? ?? ff 8d 45 f8 50 68 00 04 00 00 8d 85 a8 f9 ff ff 50 57 e8 ?? ?? ?? ff 6a 00 8d 95 a8 f9 ff ff 8b 4d f8 8d 85 a8 fd ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}