
rule TrojanDownloader_Win32_Banload_ACP{
	meta:
		description = "TrojanDownloader:Win32/Banload.ACP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 3d 16 04 0f 85 90 09 05 00 e8 90 00 } //02 00 
		$a_03_1 = {74 1e 8d 45 90 01 01 50 b9 01 00 00 00 8b d3 8b 45 90 01 01 e8 90 01 04 8b 55 90 01 01 8d 45 90 01 01 e8 90 01 04 43 4e 0f 85 90 00 } //01 00 
		$a_03_2 = {23 64 20 22 90 02 02 48 90 02 01 4b 90 02 02 45 90 02 02 59 90 02 02 5f 90 00 } //01 00 
		$a_03_3 = {23 2e 6a 23 90 02 01 70 90 02 02 67 90 00 } //01 00 
		$a_03_4 = {2f 23 23 69 6e 90 02 02 66 90 02 02 65 90 02 02 63 90 02 02 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}