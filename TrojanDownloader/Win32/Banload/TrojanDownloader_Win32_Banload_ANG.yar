
rule TrojanDownloader_Win32_Banload_ANG{
	meta:
		description = "TrojanDownloader:Win32/Banload.ANG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 eb 05 be 01 00 00 00 8b 45 90 01 01 0f b6 5c 30 ff 33 5d 90 01 01 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 90 00 } //01 00 
		$a_02_1 = {83 38 06 7c 90 14 33 db 6a 00 6a 00 8b c7 e8 90 01 04 50 8b c6 e8 90 01 04 50 53 6a 00 e8 90 01 04 83 f8 20 0f 97 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}