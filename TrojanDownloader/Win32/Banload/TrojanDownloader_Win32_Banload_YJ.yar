
rule TrojanDownloader_Win32_Banload_YJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.YJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 3e 03 7c b5 80 3b 00 74 1f 8b 15 90 01 04 a1 90 01 04 e8 90 01 04 ff 05 90 01 04 ff 4d fc 0f 85 90 00 } //01 00 
		$a_01_1 = {5a 3a 5c 50 72 6f 6a 65 74 6f 73 5c 6e 65 77 68 6f 70 65 5c 63 66 67 5c 76 64 62 5c 6c 69 62 5c 56 44 42 5f } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_YJ_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.YJ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {5a 3a 5c 50 72 6f 6a 65 74 6f 73 5c 6e 65 77 68 6f 70 65 5c 63 66 67 5c 76 64 62 5c 6c 69 62 5c 56 44 42 5f 49 4e 44 2e 64 70 72 } //02 00 
		$a_01_1 = {53 00 56 00 43 00 48 00 4f 00 53 00 54 00 } //02 00 
		$a_01_2 = {56 44 42 5f 49 4e 44 2e 63 70 6c } //00 00 
	condition:
		any of ($a_*)
 
}