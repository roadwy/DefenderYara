
rule TrojanDownloader_Win32_Banload_ANZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ANZ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {c7 45 e8 07 00 00 00 6a 00 8d 45 e8 50 e8 90 01 04 83 f8 01 1b c0 40 3c 01 75 17 6a 00 6a 01 68 90 00 } //05 00 
		$a_03_1 = {54 65 6d 70 00 00 00 00 90 01 2c 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_01_2 = {69 70 63 6f 6e 66 69 67 20 2f 72 65 6e 65 77 00 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 62 72 00 } //01 00 
		$a_01_3 = {4f 20 41 64 6f 62 65 20 52 65 61 64 65 72 20 6e e3 6f 20 70 f4 64 65 20 61 62 72 69 72 20 27 00 } //01 00 
		$a_01_4 = {43 4d 44 20 2f 43 20 43 6f 70 79 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}