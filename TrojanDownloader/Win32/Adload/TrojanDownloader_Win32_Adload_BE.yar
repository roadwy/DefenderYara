
rule TrojanDownloader_Win32_Adload_BE{
	meta:
		description = "TrojanDownloader:Win32/Adload.BE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 6f 67 6f 6e 4e 61 6d 65 90 02 05 53 4f 46 54 57 41 52 45 5c 53 6f 66 74 66 79 5c 50 6c 75 67 4e 61 6d 65 90 00 } //01 00 
		$a_03_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 69 61 6e 6d 2e 63 6f 6d 2f 4d 61 69 6e 44 6c 6c 2f 53 6f 66 74 53 69 7a 65 2e 61 73 70 90 02 0a 46 69 6e 64 20 66 6c 79 20 64 6c 6c 90 00 } //01 00 
		$a_03_2 = {49 6e 73 74 61 6c 6c 4d 79 44 6c 6c 90 02 05 72 75 6e 64 6c 6c 33 32 90 00 } //01 00 
		$a_03_3 = {2f 66 6c 79 6d 79 2e 64 6c 6c 90 02 05 53 65 72 76 65 72 46 69 6c 65 53 69 7a 65 3d 25 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}