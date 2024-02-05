
rule TrojanDownloader_Win32_Cmjdown_G{
	meta:
		description = "TrojanDownloader:Win32/Cmjdown.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {6a 02 6a fc 8d 45 f4 50 e8 90 01 03 ff 6a 04 8d 45 f0 50 8d 45 f4 50 e8 90 01 03 ff 6a 02 8b 45 f0 83 c0 04 f7 d8 50 8d 45 f4 50 e8 90 01 03 ff 90 00 } //01 00 
		$a_03_1 = {6a 00 6a 00 ff 75 14 6a 00 6a 01 ff 75 10 ff 75 0c e8 90 01 03 00 89 07 83 3f ff 75 04 31 c0 eb 0f 6a 00 ff 37 e8 90 01 03 00 89 47 08 90 00 } //01 00 
		$a_00_2 = {48 54 54 50 2d 43 4d 4a 2d 44 4f 57 4e 4c 4f 41 44 } //00 00 
	condition:
		any of ($a_*)
 
}