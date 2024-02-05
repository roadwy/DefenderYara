
rule TrojanDownloader_Win32_Banload_ADA{
	meta:
		description = "TrojanDownloader:Win32/Banload.ADA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 3d 16 04 0f 85 81 08 00 00 8d 55 ec b8 } //01 00 
		$a_01_1 = {23 72 23 65 23 67 20 61 64 23 23 64 20 22 48 23 4b 23 45 59 23 5f 43 55 23 52 52 23 45 4e 23 54 } //01 00 
		$a_01_2 = {2e 23 23 63 23 23 23 70 23 23 23 23 6c 00 } //01 00 
		$a_01_3 = {2e 23 23 6a 23 23 70 23 67 00 } //01 00 
		$a_01_4 = {23 63 3a 23 5c 23 77 23 23 69 23 6e } //01 00 
		$a_01_5 = {2f 23 3f 23 63 68 23 23 61 76 23 65 3d 23 78 23 63 23 68 61 23 76 65 23 26 75 23 72 23 6c 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}