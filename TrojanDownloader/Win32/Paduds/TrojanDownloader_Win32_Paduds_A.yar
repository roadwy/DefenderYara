
rule TrojanDownloader_Win32_Paduds_A{
	meta:
		description = "TrojanDownloader:Win32/Paduds.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {0f 84 54 01 00 00 c6 45 f1 5a c6 45 f0 00 6a 00 6a 08 } //03 00 
		$a_03_1 = {7c 22 43 33 f6 ff 75 f8 8b 45 f4 ff 34 b0 68 90 01 04 8d 45 f8 ba 03 00 00 00 90 00 } //01 00 
		$a_01_2 = {68 73 74 3d 00 } //01 00 
		$a_01_3 = {64 64 73 3d 00 } //01 00 
		$a_01_4 = {61 75 70 3d 00 } //01 00 
		$a_01_5 = {5c 73 79 73 74 65 6d 5c 63 6d 64 00 } //00 00  獜獹整屭浣d
	condition:
		any of ($a_*)
 
}