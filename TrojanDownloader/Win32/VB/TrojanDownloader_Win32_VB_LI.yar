
rule TrojanDownloader_Win32_VB_LI{
	meta:
		description = "TrojanDownloader:Win32/VB.LI,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4a 00 53 00 49 00 4b 00 4a 00 49 00 4b 00 39 00 35 00 32 00 34 00 } //01 00  JSIKJIK9524
		$a_01_1 = {6d 6f 64 5f 56 61 72 69 61 76 65 69 73 00 00 00 73 6d 63 66 67 00 00 00 10 00 00 00 4a 00 53 00 48 00 4e 00 46 00 49 00 55 00 59 00 } //01 00 
		$a_01_2 = {6d 6f 64 5f 45 6e 63 72 69 70 74 00 10 00 00 00 4a 00 53 00 48 00 4e 00 46 00 49 00 55 00 59 00 } //0a 00 
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}