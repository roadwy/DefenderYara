
rule TrojanDownloader_Win32_Carberp_BV_bit{
	meta:
		description = "TrojanDownloader:Win32/Carberp.BV!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 c7 45 f0 eb fe cc cc 8b 06 ff 76 08 89 45 f8 a1 90 01 03 00 89 45 ec e8 90 01 03 00 90 00 } //01 00 
		$a_03_1 = {8b 45 08 89 45 90 01 01 58 53 68 00 00 00 08 50 89 45 90 01 01 8d 45 90 01 01 50 8d 45 90 01 01 c7 45 90 01 01 18 00 00 00 50 68 1f 00 0f 00 8d 45 90 01 01 89 5d 90 01 01 50 89 5d 90 01 01 89 5d 90 01 01 89 5d 90 01 01 ff 15 90 00 } //01 00 
		$a_03_2 = {8b 47 fc 48 03 c2 23 c1 74 1b 50 8b 07 03 c3 50 8b 47 f8 03 45 08 50 e8 90 01 03 00 8b 4d f4 83 c4 0c 8b 55 0c 90 00 } //01 00 
		$a_03_3 = {6a 40 68 00 30 00 00 68 90 01 03 00 56 ff 37 ff 15 90 01 03 00 89 45 08 85 c0 0f 84 cc 00 00 00 8d 85 90 01 03 ff 50 ff 77 04 ff 15 90 01 03 00 85 c0 79 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}