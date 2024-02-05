
rule TrojanDownloader_Win32_Banzlirb_A{
	meta:
		description = "TrojanDownloader:Win32/Banzlirb.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 61 69 6e 74 69 6d 61 32 30 31 34 2e 63 6f 6d 2e 62 72 2f } //02 00 
		$a_01_1 = {67 62 2f 70 69 72 61 74 75 62 61 2e 65 78 65 } //02 00 
		$a_01_2 = {2f 67 62 2f 70 69 72 61 72 61 2e 65 78 65 } //04 00 
		$a_01_3 = {34 73 68 61 72 65 64 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 50 6e 45 57 7a 4c 4a 66 62 61 } //01 00 
		$a_01_4 = {2f 74 65 72 63 65 69 72 6f 2e 72 61 72 3f } //04 00 
		$a_01_5 = {63 6c 2e 6c 79 2f 31 34 30 31 30 56 32 48 33 64 31 59 } //01 00 
		$a_01_6 = {2f 64 6f 77 6e 6c 6f 61 64 2f 73 65 67 75 6e 64 6f 2e 7a 69 70 } //00 00 
		$a_00_7 = {e7 2b 00 00 00 } //00 27 
	condition:
		any of ($a_*)
 
}