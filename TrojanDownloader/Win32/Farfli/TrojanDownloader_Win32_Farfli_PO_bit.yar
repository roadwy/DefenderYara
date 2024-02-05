
rule TrojanDownloader_Win32_Farfli_PO_bit{
	meta:
		description = "TrojanDownloader:Win32/Farfli.PO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 c2 7a 80 f2 19 88 14 01 41 3b ce 7c ef } //01 00 
		$a_03_1 = {4d c6 44 24 90 01 01 6f c6 44 24 90 01 01 7a c6 44 24 90 01 01 69 c6 84 24 90 01 04 6c c6 84 24 90 01 04 6c c6 84 24 90 01 04 61 c6 84 24 90 01 04 2f c6 84 24 90 01 04 34 c6 84 24 90 01 04 2e c6 84 24 90 01 04 30 c6 84 24 90 01 04 20 c6 84 24 90 01 04 28 c6 84 24 90 01 04 63 90 00 } //01 00 
		$a_01_2 = {8b 46 1c 8d 14 90 8b 04 0a 03 c1 5e 59 } //00 00 
	condition:
		any of ($a_*)
 
}