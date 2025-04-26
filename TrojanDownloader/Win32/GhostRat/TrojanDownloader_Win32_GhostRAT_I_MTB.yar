
rule TrojanDownloader_Win32_GhostRAT_I_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 44 50 ff 15 ?? ?? 41 00 53 8b f8 66 c7 44 24 34 02 00 ff 15 ?? ?? 41 00 66 89 44 24 32 8b 4f 0c 6a 10 8b 11 8d 4c 24 34 51 8b 02 8b 56 08 52 89 44 24 40 ff 15 } //2
		$a_01_1 = {c6 44 24 28 4b c6 44 24 2a 52 c6 44 24 2b 4e c6 44 24 2d 4c c6 44 24 2e 33 c6 44 24 2f 32 c6 44 24 30 2e c6 44 24 31 64 } //2
		$a_01_2 = {c6 44 24 14 4b c6 44 24 16 52 c6 44 24 17 4e c6 44 24 19 4c c6 44 24 1a 33 c6 44 24 1b 32 c6 44 24 1c 2e c6 44 24 1d 64 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}