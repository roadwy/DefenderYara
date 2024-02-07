
rule TrojanDownloader_Win32_Adload_DG{
	meta:
		description = "TrojanDownloader:Win32/Adload.DG,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {64 00 5f 00 63 00 5f 00 62 00 5f 00 70 00 5f 00 5f 00 } //05 00  d_c_b_p__
		$a_01_1 = {5c 6b 69 6c 6c 61 2e 65 78 65 00 } //05 00 
		$a_01_2 = {74 65 6d 70 25 30 32 64 2e 65 78 65 00 } //05 00 
		$a_01_3 = {74 65 6d 70 25 30 33 64 2e 7a 69 70 00 } //01 00 
		$a_01_4 = {77 77 77 2e 61 64 62 6f 6e 73 6b 69 6c 6c 67 61 6d 65 2e 63 6f 6d 00 } //01 00 
		$a_01_5 = {77 77 77 2e 76 61 64 73 6b 69 6c 6c 67 61 6d 65 2e 63 6f 6d 00 } //01 00 
		$a_01_6 = {77 77 77 2e 76 61 64 63 65 6e 74 65 72 67 61 6d 65 2e 63 6f 6d 00 } //01 00 
		$a_01_7 = {77 77 77 2e 35 6e 69 75 78 78 2e 63 6f 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}