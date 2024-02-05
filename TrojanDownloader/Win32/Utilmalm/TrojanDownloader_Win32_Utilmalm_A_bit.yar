
rule TrojanDownloader_Win32_Utilmalm_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Utilmalm.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 5a 1a 83 90 01 02 03 5a 16 e2 f5 e9 90 00 } //02 00 
		$a_01_1 = {73 16 8b 55 f8 03 55 fc 0f b6 02 83 f0 2b 8b 4d f8 03 4d fc 88 01 eb } //01 00 
		$a_03_2 = {50 8b 4d 08 8b 91 90 01 04 ff d2 90 00 } //01 00 
		$a_03_3 = {50 8b 4d fc 51 8b 55 08 8b 82 90 01 04 ff d0 90 00 } //01 00 
		$a_01_4 = {50 e8 00 00 00 00 58 05 ff 00 00 00 05 0e 01 00 00 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}