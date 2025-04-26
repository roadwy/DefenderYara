
rule TrojanDownloader_Win32_GhostRAT_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c8 31 d2 f7 f6 8b 45 ?? 8a 04 10 30 04 0b 41 } //2
		$a_03_1 = {89 f0 31 d2 f7 f1 8b 45 ?? 8a 04 10 30 04 33 46 } //2
		$a_03_2 = {f7 f6 8b 45 ?? 01 d0 0f b6 00 31 d8 88 01 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}