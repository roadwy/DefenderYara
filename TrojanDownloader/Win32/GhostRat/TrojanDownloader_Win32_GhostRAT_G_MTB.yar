
rule TrojanDownloader_Win32_GhostRAT_G_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 8b f8 66 c7 44 24 14 02 00 e8 90 01 02 00 00 66 89 44 24 12 8b 47 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4e 08 51 89 54 24 20 e8 90 00 } //2
		$a_03_1 = {8b f0 66 a1 64 a1 40 00 50 66 c7 44 24 18 02 00 e8 90 01 02 00 00 66 89 44 24 16 8b 4e 0c 6a 10 8b 11 8d 4c 24 18 51 8b 02 8b 15 f0 ea 40 00 52 89 44 24 24 e8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}