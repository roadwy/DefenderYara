
rule TrojanDownloader_Win32_Brucryp_B{
	meta:
		description = "TrojanDownloader:Win32/Brucryp.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 65 00 72 00 74 00 5f 00 76 00 25 00 64 00 5f 00 25 00 64 00 2e 00 74 00 70 00 6c 00 00 00 } //01 00 
		$a_01_1 = {67 64 6d 76 65 64 00 00 2e 00 74 00 70 00 6c 00 00 00 64 00 30 00 61 00 } //01 00 
		$a_01_2 = {65 00 76 00 65 00 6e 00 74 00 74 00 6f 00 73 00 79 00 6e 00 63 00 74 00 72 00 74 00 68 00 00 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}