
rule TrojanDownloader_Win32_PrivateLoader_KK_MTB{
	meta:
		description = "TrojanDownloader:Win32/PrivateLoader.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 8b 4c 24 14 83 f0 11 8b 3d ?? ?? ?? ?? 33 ca 89 44 24 30 89 4c 24 34 c7 44 24 20 11 00 00 00 89 54 24 24 c7 44 24 18 4c 71 03 00 89 54 24 1c c7 44 24 28 7e e0 00 00 89 54 24 2c 8b 54 24 18 8b 74 24 1c 8b 44 24 20 03 d0 } //20
		$a_01_1 = {89 74 24 44 8b 44 24 28 8b 4c 24 2c 8b 54 24 30 8b 74 24 34 2b d0 89 54 24 38 1b f1 89 74 24 3c 8b 74 24 38 8b 54 24 3c 8b 4c 24 40 8b 44 24 44 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}