
rule TrojanDownloader_Win32_Small_NO{
	meta:
		description = "TrojanDownloader:Win32/Small.NO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6d 64 20 2f 63 20 73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 } //01 00 
		$a_00_1 = {75 72 6c 6d 30 6e 2e 64 6c 6c } //01 00 
		$a_03_2 = {83 f8 08 7d 13 8b 4d dc 8a 0c 08 81 f1 8a 00 00 00 88 90 01 03 40 eb e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}