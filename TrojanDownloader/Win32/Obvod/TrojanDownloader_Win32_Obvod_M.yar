
rule TrojanDownloader_Win32_Obvod_M{
	meta:
		description = "TrojanDownloader:Win32/Obvod.M,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 fe 8a 44 0c 90 01 01 8a 94 14 90 01 04 32 c2 88 44 0c 90 01 01 41 83 f9 20 7c e4 90 00 } //01 00 
		$a_00_1 = {5c 2a 61 64 2a 74 78 74 00 } //01 00 
		$a_00_2 = {70 6f 70 75 70 6d 67 72 00 } //01 00 
		$a_00_3 = {2e 70 68 70 3f 61 3d 25 73 26 62 3d 25 64 26 63 3d 25 64 00 } //00 00  瀮灨愿┽♳㵢搥挦┽d
		$a_00_4 = {7e 15 00 } //00 0e 
	condition:
		any of ($a_*)
 
}