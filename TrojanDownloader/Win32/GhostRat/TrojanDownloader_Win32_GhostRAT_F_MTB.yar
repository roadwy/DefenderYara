
rule TrojanDownloader_Win32_GhostRAT_F_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 50 ff 15 90 01 02 40 00 8b 4c 24 28 8b 90 01 01 51 66 c7 44 24 14 02 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}