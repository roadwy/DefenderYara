
rule TrojanDownloader_Win32_Egapel_D{
	meta:
		description = "TrojanDownloader:Win32/Egapel.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d6 3b c7 72 fa 5f 5e c3 } //01 00 
		$a_01_1 = {83 fe 2d 7e 05 83 ee 2d eb 03 83 c6 0f } //01 00 
		$a_03_2 = {6a 7c 56 e8 90 01 02 00 00 83 c4 0c 90 03 04 04 85 c0 0f 84 3b c3 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}