
rule TrojanDownloader_Win32_Upatre_CL{
	meta:
		description = "TrojanDownloader:Win32/Upatre.CL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d1 85 c0 74 65 31 c0 50 ff 35 90 01 02 40 00 50 6a 00 6a 4d 68 15 01 00 00 6a 31 6a 41 68 00 00 cf 00 90 00 } //01 00 
		$a_01_1 = {56 57 83 7d 0c 01 74 0e 83 7d 0c 05 74 15 83 7d 0c 07 74 13 eb 15 b8 } //01 00 
		$a_03_2 = {e8 00 00 00 00 5b 8b b3 90 01 02 00 00 56 03 76 3c 66 a9 90 01 02 57 57 6a 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}