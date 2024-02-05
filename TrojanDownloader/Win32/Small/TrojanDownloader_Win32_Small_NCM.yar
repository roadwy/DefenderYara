
rule TrojanDownloader_Win32_Small_NCM{
	meta:
		description = "TrojanDownloader:Win32/Small.NCM,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 65 72 76 69 63 65 73 2e 65 78 65 } //0a 00 
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00 
		$a_01_2 = {5c 67 6b 6a 6e 72 2e 63 6f 6e 66 } //0a 00 
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //0a 00 
		$a_01_4 = {5c 6f 75 74 00 25 73 25 73 } //01 00 
		$a_01_5 = {57 69 6e 4d 65 64 69 61 } //01 00 
		$a_01_6 = {57 69 6e 55 70 67 72 61 64 65 } //01 00 
		$a_00_7 = {75 6e 65 78 70 61 6e 64 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}