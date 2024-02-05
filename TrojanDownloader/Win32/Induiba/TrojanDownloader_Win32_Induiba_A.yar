
rule TrojanDownloader_Win32_Induiba_A{
	meta:
		description = "TrojanDownloader:Win32/Induiba.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 25 73 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 } //01 00 
		$a_01_1 = {2f 63 6f 75 6e 74 2e 61 73 70 3f } //01 00 
		$a_00_2 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f } //01 00 
		$a_00_3 = {62 61 69 64 75 2e 69 6e 66 6f 2f 46 69 6c 65 73 2f 64 65 66 61 75 6c 74 2e 6a 70 67 } //00 00 
	condition:
		any of ($a_*)
 
}