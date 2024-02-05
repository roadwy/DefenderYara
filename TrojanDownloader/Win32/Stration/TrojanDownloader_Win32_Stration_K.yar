
rule TrojanDownloader_Win32_Stration_K{
	meta:
		description = "TrojanDownloader:Win32/Stration.K,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {56 43 32 30 58 43 30 30 55 } //0a 00 
		$a_02_1 = {5b 72 1e 80 3e 4d 75 19 80 7e 01 5a 74 2a 8b 15 90 01 03 00 69 d2 90 00 } //0a 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 2d 32 2e 63 6f 6d 2f 90 02 08 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}