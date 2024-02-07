
rule TrojanDownloader_Win32_Tofsee_D{
	meta:
		description = "TrojanDownloader:Win32/Tofsee.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 75 0c ff 75 08 6a 50 50 e8 90 01 04 8b f8 83 c4 40 85 ff 75 11 68 60 ea 00 00 43 ff 15 90 01 04 3b 5d 18 7c 90 00 } //01 00 
		$a_03_1 = {3b c3 74 0e c6 40 01 6a c6 40 02 70 c6 40 03 67 eb 90 01 01 8d 85 90 01 02 ff ff 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}