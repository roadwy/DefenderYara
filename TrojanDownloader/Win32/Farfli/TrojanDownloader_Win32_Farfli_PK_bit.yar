
rule TrojanDownloader_Win32_Farfli_PK_bit{
	meta:
		description = "TrojanDownloader:Win32/Farfli.PK!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 c2 90 01 01 80 f2 90 01 01 88 14 01 41 3b ce 7c 90 00 } //01 00 
		$a_03_1 = {8a 11 8a 18 88 19 41 3b c8 88 10 74 90 01 01 48 3b c8 75 90 00 } //01 00 
		$a_03_2 = {8b 06 8b c8 8b d0 c1 e9 90 01 01 c1 ea 90 01 01 83 e1 90 01 01 83 e2 90 01 01 c1 e8 90 00 } //01 00 
		$a_03_3 = {75 c6 44 24 90 01 01 72 88 5c 24 1e c6 44 24 90 01 01 6d c6 44 24 90 01 01 6f c6 44 24 90 01 01 6e c6 44 24 90 01 01 2e c6 44 24 90 01 01 64 88 5c 24 24 88 5c 24 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}