
rule TrojanDownloader_Win32_Banload_BBO{
	meta:
		description = "TrojanDownloader:Win32/Banload.BBO,SIGNATURE_TYPE_PEHSTR,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 39 32 2e 31 36 39 2e 39 30 2e 32 39 } //01 00 
		$a_01_1 = {61 63 72 6f 6e 79 6d 73 6c 65 6b 73 2e 65 78 65 } //01 00 
		$a_01_2 = {67 75 6e 79 6f 75 74 6c 2e 65 78 65 } //01 00 
		$a_01_3 = {41 73 77 61 6e 79 6f 75 2e 65 78 65 } //01 00 
		$a_01_4 = {55 73 65 73 5f 70 63 2e 7a 6c 69 62 } //00 00 
		$a_01_5 = {00 5d 04 00 00 } //52 3c 
	condition:
		any of ($a_*)
 
}