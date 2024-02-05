
rule TrojanDownloader_Win32_Small_AAAF{
	meta:
		description = "TrojanDownloader:Win32/Small.AAAF,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 68 65 69 6e 73 74 61 6c 6c 73 2e 63 6f 6d } //01 00 
		$a_01_1 = {6c 64 69 6e 66 6f 2e 6c 64 72 } //01 00 
		$a_01_2 = {6c 64 63 6f 72 65 5f 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_01_3 = {6c 64 63 6f 72 65 5f 67 75 61 72 64 } //01 00 
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 } //01 00 
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00 
		$a_01_6 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //00 00 
	condition:
		any of ($a_*)
 
}