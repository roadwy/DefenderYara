
rule TrojanDownloader_Win32_GhostRAT_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 7d e8 10 8b 45 d4 73 90 01 01 8d 45 d4 8b 8c b5 78 fd ff ff 51 50 ff 15 90 01 04 83 c4 08 85 c0 74 90 01 01 46 83 fe 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}