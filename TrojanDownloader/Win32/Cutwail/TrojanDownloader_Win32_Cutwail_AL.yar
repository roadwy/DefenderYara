
rule TrojanDownloader_Win32_Cutwail_AL{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 3e 50 45 00 00 75 18 8d 4d 08 51 8d 4d fc 51 ff 75 0c 50 ff 15 90 01 04 8b 45 08 89 46 58 90 00 } //01 00 
		$a_03_1 = {85 c0 75 37 a1 90 01 04 56 56 56 56 56 57 56 6a 02 6a 01 53 56 ff 34 85 90 00 } //02 00 
		$a_01_2 = {6e 64 69 73 5f 76 65 72 } //01 00  ndis_ver
		$a_01_3 = {b8 cc 11 00 00 ba 00 03 fe 7f ff 12 } //01 00 
		$a_01_4 = {be 3f 20 01 00 56 ff 75 fc ff d7 53 8d 45 e0 } //01 00 
		$a_01_5 = {64 a1 24 01 00 00 8b 40 44 8b f8 81 c7 c8 00 00 00 05 88 00 00 00 8b 00 bb ec 00 00 00 03 d8 8b 0b 81 f9 53 79 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}