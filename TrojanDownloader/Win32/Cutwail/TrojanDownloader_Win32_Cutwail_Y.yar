
rule TrojanDownloader_Win32_Cutwail_Y{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 54 5d 64 ff 35 18 00 00 00 58 5d c3 } //01 00 
		$a_03_1 = {c7 45 e0 b9 79 37 9e 90 03 03 04 ff 75 e0 58 8b 45 e0 90 00 } //01 00 
		$a_01_2 = {68 20 00 cc 00 68 c8 00 00 00 68 96 00 00 00 6a 00 6a 00 ff 35 } //00 00 
	condition:
		any of ($a_*)
 
}