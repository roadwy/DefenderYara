
rule TrojanDownloader_Win32_BrobanLaw_B{
	meta:
		description = "TrojanDownloader:Win32/BrobanLaw.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 01 00 00 00 8b 45 0c 8b 55 fc 0f b7 5c 50 fe 03 5d 10 8b c3 33 d2 52 50 8d 45 f0 e8 } //01 00 
		$a_03_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 58 c3 e9 90 09 05 00 68 90 00 } //01 00 
		$a_01_2 = {8b fe 03 f8 0f b6 17 2a 55 10 88 17 40 49 75 f0 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}