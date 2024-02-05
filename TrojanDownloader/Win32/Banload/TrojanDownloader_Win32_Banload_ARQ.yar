
rule TrojanDownloader_Win32_Banload_ARQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 5c 52 75 6e 20 2f 66 20 2f 76 20 65 76 78 20 2f 64 20 22 72 65 67 73 76 72 33 32 } //01 00 
		$a_03_1 = {5c 65 76 78 2e 72 33 78 00 72 90 02 06 90 04 06 07 68 74 70 5b 5d 3a 2f 90 00 } //00 00 
		$a_00_2 = {78 } //a2 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_ARQ_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.ARQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {fc b9 2b 00 00 00 b0 00 f3 aa 8b 45 90 01 01 89 44 24 04 90 00 } //01 00 
		$a_01_1 = {3f 63 68 61 76 65 3d 78 63 68 61 76 65 26 75 72 6c 3d 69 6e 66 65 63 74 65 64 5f } //01 00 
		$a_01_2 = {61 64 64 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 66 20 2f 76 20 65 76 78 20 2f 64 20 22 72 65 67 73 76 72 33 32 20 2f 73 } //00 00 
	condition:
		any of ($a_*)
 
}