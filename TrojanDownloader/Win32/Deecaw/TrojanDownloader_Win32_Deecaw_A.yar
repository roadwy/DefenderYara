
rule TrojanDownloader_Win32_Deecaw_A{
	meta:
		description = "TrojanDownloader:Win32/Deecaw.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {2e 70 68 70 00 55 73 65 72 44 61 74 61 } //01 00 
		$a_01_1 = {2f 69 63 6f 75 6e 74 2e } //02 00 
		$a_01_2 = {75 69 64 3d 25 73 26 70 63 6f 64 65 73 3d 25 73 } //02 00 
		$a_01_3 = {75 69 64 3d 25 73 00 00 50 4f 53 54 } //01 00 
		$a_01_4 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //02 00 
		$a_01_5 = {5f 64 6f 77 6e 6c 6f 61 64 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //02 00 
		$a_01_6 = {6c 64 63 6f 72 65 5f } //00 00 
	condition:
		any of ($a_*)
 
}