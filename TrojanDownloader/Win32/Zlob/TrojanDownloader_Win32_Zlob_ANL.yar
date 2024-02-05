
rule TrojanDownloader_Win32_Zlob_ANL{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANL,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 04 00 "
		
	strings :
		$a_03_0 = {8a 47 01 47 3a c3 75 f8 be 90 01 02 40 00 66 a5 8d bd f0 fe ff ff 4f 8a 47 01 47 3a c3 75 f8 be 90 01 02 40 00 a5 a5 a5 a5 90 00 } //05 00 
		$a_00_1 = {57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 } //01 00 
		$a_00_2 = {61 77 65 72 25 64 2e 62 61 74 } //01 00 
		$a_00_3 = {25 73 5c 6c 6c 25 73 25 64 2e 65 78 65 } //01 00 
		$a_00_4 = {6f 67 6c 65 2e } //01 00 
		$a_00_5 = {68 53 63 6f 70 65 73 } //01 00 
		$a_00_6 = {72 6d 64 69 72 20 22 25 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}