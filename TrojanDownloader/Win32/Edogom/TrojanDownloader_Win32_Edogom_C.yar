
rule TrojanDownloader_Win32_Edogom_C{
	meta:
		description = "TrojanDownloader:Win32/Edogom.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 7a 68 6a 69 5d 2a 2e 27 28 17 1e 58 63 60 62 52 64 58 50 59 51 14 00 } //01 00 
		$a_01_1 = {3e 74 63 71 67 6d 70 39 00 } //01 00 
		$a_01_2 = {3e 30 73 62 70 66 6c 6f 38 00 } //01 00  〾扳晰潬8
		$a_02_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 33 64 76 69 64 65 6f 2e 72 75 2f 6e 65 77 2f 33 64 2f 90 02 10 2e 70 68 70 3f 70 6c 61 79 3d 31 30 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}