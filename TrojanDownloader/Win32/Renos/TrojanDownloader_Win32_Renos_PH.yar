
rule TrojanDownloader_Win32_Renos_PH{
	meta:
		description = "TrojanDownloader:Win32/Renos.PH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 06 10 00 00 56 ff 75 0c ff d7 8b 45 18 ff 75 10 66 c7 45 d0 02 00 89 45 d4 ff 15 90 01 04 66 89 45 d2 8d 45 d0 6a 10 50 ff 75 0c ff 15 90 01 04 83 f8 ff 90 00 } //01 00 
		$a_02_1 = {6a 00 b8 60 ea 00 00 6a ff 50 50 8d 45 e4 6a 00 50 0f b7 85 6c ff ff ff 50 8d 45 c0 50 8d 45 b0 50 e8 90 01 04 83 c4 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}