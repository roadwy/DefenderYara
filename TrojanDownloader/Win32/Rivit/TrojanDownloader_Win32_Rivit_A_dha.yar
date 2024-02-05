
rule TrojanDownloader_Win32_Rivit_A_dha{
	meta:
		description = "TrojanDownloader:Win32/Rivit.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6e 69 70 20 63 2f 20 65 78 65 2e 64 6d 63 } //01 00 
		$a_01_1 = {63 2d 20 6e 65 64 64 69 68 20 77 2d 20 70 6f 6e 2d 20 65 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 } //01 00 
		$a_01_2 = {2f 2f 3a 70 74 74 68 27 28 67 6e 69 72 74 73 64 61 6f 6c 6e 77 6f 64 2e 4a 24 } //00 00 
	condition:
		any of ($a_*)
 
}