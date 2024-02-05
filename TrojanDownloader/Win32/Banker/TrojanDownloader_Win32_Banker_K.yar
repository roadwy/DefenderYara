
rule TrojanDownloader_Win32_Banker_K{
	meta:
		description = "TrojanDownloader:Win32/Banker.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {61 74 65 6e 64 69 6d 65 6e 74 6f 2d 70 65 73 73 6f 61 6c 2d 73 75 70 6f 72 74 65 2e 63 6f 6d 2f 90 02 15 2e 6a 70 67 90 00 } //01 00 
		$a_02_1 = {63 6d 64 20 2f 6b 20 63 3a 5c 57 69 6e 64 6f 77 73 5c 90 02 0f 2e 6a 70 67 90 00 } //01 00 
		$a_00_2 = {6c 65 76 65 6c 3d 22 72 65 71 75 69 72 65 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 22 } //00 00 
	condition:
		any of ($a_*)
 
}