
rule TrojanDownloader_Win32_Small_AIT{
	meta:
		description = "TrojanDownloader:Win32/Small.AIT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 2b 8d 4c 24 34 68 90 01 01 80 40 00 51 e8 90 01 02 00 00 83 c4 08 85 c0 74 0d 8d 54 24 10 52 56 e8 90 00 } //01 00 
		$a_03_1 = {b0 0a c6 44 24 90 01 01 41 c6 44 24 90 01 01 65 c6 44 24 90 01 01 70 c6 44 24 90 01 01 74 c6 44 24 90 01 01 3a c6 44 24 90 01 01 20 c6 44 24 90 01 01 2f 88 4c 24 90 09 04 00 88 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}