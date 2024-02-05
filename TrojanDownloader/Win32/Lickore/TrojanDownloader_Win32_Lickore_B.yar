
rule TrojanDownloader_Win32_Lickore_B{
	meta:
		description = "TrojanDownloader:Win32/Lickore.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 03 00 00 00 e8 90 01 04 8b 55 90 01 01 b8 90 01 04 e8 90 02 10 ff 90 02 05 68 90 01 04 68 90 01 04 8d 45 90 01 01 ba 03 00 00 00 90 00 } //01 00 
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_00_2 = {64 6f 77 6e 2e 74 6d 71 72 68 6b 73 2e 63 6f 6d 2f 64 69 73 74 } //01 00 
		$a_03_3 = {54 52 41 43 45 90 02 10 50 55 54 90 02 10 43 4f 4e 4e 45 43 54 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}