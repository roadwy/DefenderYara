
rule TrojanDownloader_Win32_Trotoawny{
	meta:
		description = "TrojanDownloader:Win32/Trotoawny,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4e 75 6c 6c 73 6f 66 74 90 02 12 76 32 2e 34 36 90 00 } //01 00 
		$a_01_1 = {fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 } //01 00 
		$a_03_2 = {68 74 74 70 3a 2f 2f 6d 6f 64 72 69 74 65 2e 69 6e 66 6f 2f 90 02 06 2f 90 02 06 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}