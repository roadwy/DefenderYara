
rule TrojanDownloader_Win32_Upatre_BN{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 54 6a 50 48 66 ab 58 66 ab 58 48 66 ab } //01 00 
		$a_00_1 = {b0 2f aa 33 c0 aa b8 c8 00 00 00 } //01 00 
		$a_00_2 = {6a 04 68 00 10 00 00 68 e4 dc a7 00 6a 00 } //00 00 
		$a_00_3 = {78 af } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Upatre_BN_2{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 03 f8 58 ff d7 66 c7 01 49 36 c6 41 02 34 83 c1 03 8b f2 81 e6 00 0e 00 00 81 fe 00 04 00 00 75 0d 5f b2 6f 5e 88 11 c6 41 01 00 5b 5d c3 } //01 00 
		$a_03_1 = {40 00 40 e2 fd ff d0 90 09 04 00 8b 0d 90 00 } //01 00 
		$a_03_2 = {40 00 92 b9 c8 00 00 00 6a 10 2b c2 23 c1 e2 fa 59 58 85 c0 0f 85 a5 fc ff ff 90 09 04 00 ff 35 90 00 } //01 00 
		$a_03_3 = {40 00 68 98 00 00 00 8b d0 59 6a 12 2b c2 23 c1 e2 fa 59 58 49 49 75 c3 90 09 04 00 ff 35 90 00 } //01 00 
		$a_01_4 = {55 8b ec 33 c0 4e 55 40 40 40 4e 40 5f a5 49 75 fc e8 } //00 00 
	condition:
		any of ($a_*)
 
}