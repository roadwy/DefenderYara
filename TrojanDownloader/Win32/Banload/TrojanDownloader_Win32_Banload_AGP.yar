
rule TrojanDownloader_Win32_Banload_AGP{
	meta:
		description = "TrojanDownloader:Win32/Banload.AGP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 06 8b 45 f4 8b 10 ff 12 8b c8 8b 16 8b 45 f4 8b 30 ff 56 0c 8b 45 f4 8b 10 ff 12 89 03 c6 45 ff 01 } //01 00 
		$a_03_1 = {83 c0 05 8d 55 90 01 01 e8 90 01 04 8b 45 90 1b 00 89 45 90 01 01 c6 45 90 01 01 0b 8d 55 90 01 01 b8 03 00 00 00 e8 90 01 04 8b 45 90 1b 05 89 45 90 01 01 c6 45 90 01 01 0b 8d 55 90 01 01 b9 02 00 00 00 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}