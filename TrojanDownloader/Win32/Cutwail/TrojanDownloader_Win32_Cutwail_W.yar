
rule TrojanDownloader_Win32_Cutwail_W{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.W,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 80 38 4d 75 0b 8b 45 08 40 80 38 5a 75 02 eb 0f } //02 00 
		$a_01_1 = {c6 00 2f 8d 45 f8 ff 00 8b 45 f8 03 45 08 c6 00 72 8d 45 f8 ff 00 8b 45 f8 03 45 08 c6 00 69 8d 45 f8 ff 00 8b 45 f8 03 45 08 c6 00 6f 8d 45 f8 ff 00 8b 45 f8 03 45 08 c6 00 3f 8d 45 f8 ff 00 } //01 00 
		$a_01_2 = {48 6f 73 74 3a 20 25 69 2e 25 69 2e 25 69 2e 25 69 25 73 } //01 00 
		$a_01_3 = {3b 25 34 2e 34 68 78 2d 25 34 2e 34 68 78 3b } //00 00 
	condition:
		any of ($a_*)
 
}