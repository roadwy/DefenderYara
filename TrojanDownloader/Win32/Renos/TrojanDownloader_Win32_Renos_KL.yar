
rule TrojanDownloader_Win32_Renos_KL{
	meta:
		description = "TrojanDownloader:Win32/Renos.KL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c4 56 50 e8 90 01 02 00 00 8b 35 90 01 04 59 59 50 ff 75 fc ff d6 89 45 f8 90 00 } //01 00 
		$a_03_1 = {81 7d 0c 2c 01 00 00 0f 8c 90 01 02 00 00 81 7d 0c 8f 01 00 00 0f 8f 90 01 02 00 00 90 00 } //01 00 
		$a_03_2 = {68 00 14 2d 00 ff 74 24 90 01 01 ff 15 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}