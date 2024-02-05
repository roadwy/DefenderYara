
rule TrojanDownloader_Win32_Banload_DI{
	meta:
		description = "TrojanDownloader:Win32/Banload.DI,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00 
		$a_01_1 = {75 62 65 2d 31 36 37 2e 70 6f 70 2e 63 6f 6d 2e 62 72 2f 72 65 70 6f 73 69 74 6f 72 69 6f 2f 37 37 36 38 37 2f 6d 65 75 73 69 74 65 } //01 00 
		$a_01_2 = {32 30 31 2e 32 32 2e 31 36 34 2e 31 38 31 2f 6d 65 6e 73 61 67 65 6d } //01 00 
		$a_01_3 = {73 69 78 79 61 68 62 69 2e 65 78 65 } //01 00 
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}