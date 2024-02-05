
rule TrojanDownloader_Win32_Upatre_AL{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 06 40 40 46 3d 66 64 72 65 e0 f4 } //01 00 
		$a_01_1 = {ad 33 c3 43 ab e2 f9 } //01 00 
		$a_01_2 = {5b 80 e7 f0 6a 05 8d 7d 14 32 db } //01 00 
		$a_01_3 = {66 ad 66 85 c0 74 f9 8b fe eb 16 3c 00 75 b2 04 30 66 ab } //01 00 
		$a_01_4 = {61 37 25 73 25 73 00 } //01 00 
		$a_01_5 = {8b 06 40 ba 67 64 72 65 40 4a 46 3b c2 e0 f1 } //01 00 
		$a_01_6 = {68 38 25 73 25 73 00 } //01 00 
		$a_01_7 = {66 ad 03 c3 ab 33 c0 e2 f7 } //01 00 
		$a_03_8 = {8b fe ad 33 45 90 01 01 ff 45 90 01 01 89 07 90 00 } //01 00 
		$a_03_9 = {ab 49 75 fc 57 b9 90 01 04 41 89 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}