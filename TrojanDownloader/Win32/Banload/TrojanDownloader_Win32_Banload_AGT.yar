
rule TrojanDownloader_Win32_Banload_AGT{
	meta:
		description = "TrojanDownloader:Win32/Banload.AGT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 10 8b 45 ec 8b 00 e8 90 01 04 33 c0 5a 59 59 64 89 10 eb 90 14 68 90 01 02 00 00 e8 90 00 } //01 00 
		$a_01_1 = {0f b6 44 30 ff 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4 } //00 00 
	condition:
		any of ($a_*)
 
}