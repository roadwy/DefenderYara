
rule TrojanDownloader_Win32_Dofoil_AE{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 75 06 74 04 90 01 04 5b eb 90 00 } //01 00 
		$a_03_1 = {83 b8 a4 00 00 00 06 7c 90 01 01 eb 90 00 } //02 00 
		$a_03_2 = {0f b6 40 02 eb 90 01 02 40 eb 90 01 05 b9 90 01 04 eb 90 01 05 eb 90 01 02 eb 90 01 02 f7 e1 eb 90 01 06 01 d8 74 07 75 05 90 01 05 50 c3 90 00 } //02 00 
		$a_03_3 = {0f b6 46 68 eb 90 01 02 40 74 07 75 05 90 01 05 68 90 01 04 75 04 74 02 90 01 02 59 eb 90 01 02 f7 e1 eb 90 01 06 01 d8 eb 90 01 04 ff e0 90 00 } //04 00 
		$a_03_4 = {e8 00 00 00 00 75 06 74 04 90 01 04 5e eb 90 01 02 81 ee 90 01 04 eb 90 01 02 eb 90 01 03 eb 90 01 06 01 c6 eb 90 01 05 89 f7 eb 90 01 05 eb 90 01 02 ac eb 90 01 06 30 d0 aa e2 90 01 01 75 06 74 04 90 00 } //00 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}