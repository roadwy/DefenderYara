
rule TrojanDownloader_Win32_PrivateLoader_KKA_MTB{
	meta:
		description = "TrojanDownloader:Win32/PrivateLoader.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 8b 4c 24 14 83 f0 ?? ?? ?? ?? ?? ?? ?? 33 ca 89 44 24 30 89 4c 24 34 c7 44 24 20 ?? ?? ?? ?? 89 54 24 24 c7 44 24 18 ?? ?? ?? ?? 89 54 24 1c c7 44 24 28 ?? ?? ?? ?? 89 54 24 2c 8b 54 24 18 8b 74 24 1c 8b 44 24 20 03 d0 } //20
		$a_01_1 = {13 f1 83 c2 01 89 54 24 40 83 d6 00 89 74 24 44 8b 44 24 28 8b 4c 24 2c 8b 54 24 30 8b 74 24 34 2b d0 89 54 24 38 1b f1 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}