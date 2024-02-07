
rule TrojanDownloader_Win32_Chevaloi_A{
	meta:
		description = "TrojanDownloader:Win32/Chevaloi.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {5c 76 6d 63 5f 74 65 72 6d 90 02 10 72 75 6e 64 6c 6c 33 32 2e 65 78 65 90 02 10 65 78 70 6c 6f 72 65 72 2e 65 78 65 90 00 } //02 00 
		$a_03_1 = {4d 6f 7a 69 6c 6c 61 55 49 57 69 6e 64 6f 77 43 6c 61 73 73 90 02 10 64 6c 6c 5f 69 6e 6a 65 63 74 90 00 } //02 00 
		$a_03_2 = {66 69 72 65 66 6f 78 2e 65 78 65 00 62 75 74 74 6f 6e 90 02 10 22 25 73 22 20 2d 6e 65 77 2d 77 69 6e 64 6f 77 90 00 } //01 00 
		$a_01_3 = {73 65 72 76 69 63 65 73 2e 65 78 65 00 00 00 00 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //01 00 
		$a_01_4 = {68 74 74 70 3a 2f 2f 25 73 3a 25 69 25 73 } //00 00  http://%s:%i%s
	condition:
		any of ($a_*)
 
}