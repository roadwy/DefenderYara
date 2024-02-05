
rule TrojanDownloader_Win32_GhostRat_CBI_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRat.CBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0f 8b 56 10 fe c9 88 4d f0 3b 56 14 73 90 01 01 83 7e 14 10 8d 42 01 89 46 10 8b c6 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}