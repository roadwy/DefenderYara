
rule TrojanDownloader_Win32_Smordess_A{
	meta:
		description = "TrojanDownloader:Win32/Smordess.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 63 20 22 50 6f 77 65 72 53 68 65 6c 6c 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 } //01 00 
		$a_01_1 = {28 4e 65 77 2d 4f 62 6a 65 63 74 20 2d 63 6f 6d 20 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 29 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 27 6d 65 73 73 2e 65 78 65 27 29 } //00 00 
	condition:
		any of ($a_*)
 
}