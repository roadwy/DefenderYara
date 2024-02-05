
rule TrojanDownloader_Win32_Small_ZYB{
	meta:
		description = "TrojanDownloader:Win32/Small.ZYB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 4c 24 04 8a 01 84 c0 74 0c 04 06 88 01 8a 41 01 41 84 c0 75 f4 c3 } //01 00 
		$a_01_1 = {5f 53 74 61 72 74 52 75 6e 40 31 36 } //01 00 
		$a_01_2 = {5d 34 56 4a 3e 49 4d 3f 4c 4c 28 3e 3b 4e } //01 00 
		$a_01_3 = {62 6e 6e 6a 34 29 29 71 71 71 28 5c 5b 63 5e 6f 28 5d 69 67 } //00 00 
	condition:
		any of ($a_*)
 
}