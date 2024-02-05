
rule TrojanDownloader_Win32_Busiwoe_A{
	meta:
		description = "TrojanDownloader:Win32/Busiwoe.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 6f 65 63 64 2e 62 75 73 69 6e 65 73 73 63 6f 6e 73 75 6c 74 73 2e 6e 65 74 } //01 00 
		$a_00_1 = {4c 6f 67 6f 6e 20 75 73 65 72 20 65 72 72 21 } //01 00 
		$a_00_2 = {70 72 6f 63 65 73 73 2d 63 6d 64 2d 73 74 6f 70 70 65 64 } //01 00 
		$a_01_3 = {41 50 56 53 56 43 } //00 00 
	condition:
		any of ($a_*)
 
}