
rule TrojanDownloader_Win32_Bledox_B{
	meta:
		description = "TrojanDownloader:Win32/Bledox.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 53 75 70 64 61 74 65 2e 6c 6e 6b 00 } //01 00 
		$a_01_1 = {74 72 75 70 64 00 } //01 00 
		$a_01_2 = {2d 2d 46 61 73 63 69 73 74 46 69 72 65 77 61 6c 6c 20 31 } //01 00 
		$a_01_3 = {5c 63 66 5f 2e 62 69 6e } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}