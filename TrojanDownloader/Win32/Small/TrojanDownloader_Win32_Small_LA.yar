
rule TrojanDownloader_Win32_Small_LA{
	meta:
		description = "TrojanDownloader:Win32/Small.LA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 70 72 6f 6d 74 2e 63 63 2f 72 69 6e 67 } //01 00 
		$a_00_1 = {2f 63 20 64 65 6c 20 3e 63 3a } //01 00 
		$a_01_2 = {b9 20 00 00 00 f3 a5 8b 54 24 28 8b 4d 04 8a 44 24 2c 8b 74 24 30 89 4c 95 38 8d 7d 18 b9 08 00 00 00 88 45 02 } //00 00 
	condition:
		any of ($a_*)
 
}