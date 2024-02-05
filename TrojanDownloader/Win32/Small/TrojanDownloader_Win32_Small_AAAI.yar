
rule TrojanDownloader_Win32_Small_AAAI{
	meta:
		description = "TrojanDownloader:Win32/Small.AAAI,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 36 39 2e 33 31 2e 38 34 2e 32 32 33 2f } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 74 72 61 63 6b 68 69 74 73 2e 63 63 2f 63 6e 74 } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}