
rule TrojanDownloader_Win32_Dwyad_A{
	meta:
		description = "TrojanDownloader:Win32/Dwyad.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 ad de ad de 83 c4 20 8b 90 01 02 05 00 30 00 00 ff d0 c6 90 01 02 01 e8 90 01 04 8d 45 90 01 01 e8 90 00 } //01 00 
		$a_03_1 = {43 3a 5c 78 31 5c 75 72 6c 5c 44 6f 77 90 02 10 43 3a 5c 78 31 5c 75 72 6c 5c 6e 6c 6f 90 00 } //01 00 
		$a_00_2 = {43 3a 5c 44 77 79 5c 54 45 5c 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 } //01 00  C:\Dwy\TE\ALLUSERSPROFILE
		$a_03_3 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 00 00 00 00 ff ff ff ff 90 01 01 00 00 00 90 02 30 68 74 74 70 3a 2f 2f 90 02 30 2e 65 78 65 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}