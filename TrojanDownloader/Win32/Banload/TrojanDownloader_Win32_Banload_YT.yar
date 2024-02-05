
rule TrojanDownloader_Win32_Banload_YT{
	meta:
		description = "TrojanDownloader:Win32/Banload.YT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 76 67 73 65 74 75 70 31 2e 65 78 65 00 } //01 00 
		$a_01_1 = {61 76 67 64 61 74 61 66 69 6c 65 73 2e 65 78 65 00 } //01 00 
		$a_03_2 = {68 74 74 70 3a 2f 2f 90 02 14 2f 69 6e 63 2f 00 90 00 } //01 00 
		$a_01_3 = {67 7a 79 2e 6a 70 67 } //01 00 
		$a_01_4 = {3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c } //00 00 
	condition:
		any of ($a_*)
 
}