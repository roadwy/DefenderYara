
rule TrojanDownloader_Win32_Bocmen_A{
	meta:
		description = "TrojanDownloader:Win32/Bocmen.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 62 6f 6f 74 2e 62 69 6e 00 } //01 00 
		$a_01_1 = {5c 73 79 73 74 65 6d 33 32 5c 4d 69 63 72 6f 73 6f 66 74 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 } //01 00 
		$a_01_2 = {62 6f 74 63 6d 64 3a 00 } //01 00 
		$a_01_3 = {45 4e 44 66 69 6c 65 2e 2e 2e 00 } //01 00 
		$a_01_4 = {26 6f 73 3d 4d 61 63 58 50 57 69 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}