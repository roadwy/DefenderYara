
rule TrojanDownloader_Win32_Beebone_EU{
	meta:
		description = "TrojanDownloader:Win32/Beebone.EU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 58 59 59 59 ff 90 04 01 01 75 90 00 } //01 00 
		$a_03_1 = {ff ff 08 00 00 00 6a 63 e8 90 01 04 89 85 90 01 02 ff ff c7 85 90 01 02 ff ff 08 00 00 00 6a 6f e8 90 01 03 ff 89 85 90 01 02 ff ff c7 85 90 01 02 ff ff 08 00 00 00 6a 6d e8 90 01 03 ff 89 85 90 01 02 ff ff c7 85 90 01 02 ff ff 08 00 00 00 6a 3a e8 90 01 03 ff 89 85 90 01 02 ff ff c7 85 90 01 02 ff ff 08 00 00 00 6a 34 90 00 } //00 00 
		$a_00_2 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}