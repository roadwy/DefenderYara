
rule TrojanDownloader_Win32_Carfpos_A{
	meta:
		description = "TrojanDownloader:Win32/Carfpos.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 63 6b 59 6f 75 } //01 00 
		$a_01_1 = {26 69 70 3d 26 6f 73 3d 00 26 76 65 72 3d 00 26 6d 61 63 3d 00 63 6f 75 6e 74 2e 61 73 70 3f 6b 65 79 3d 26 75 73 65 72 69 64 3d 00 61 64 6d 69 6e 5f 69 6e 64 65 78 2e 61 73 70 } //01 00 
		$a_01_2 = {74 65 73 74 2f 3c 7c 3e 44 4e 46 2e 65 78 65 2c 4c 6f 6c 43 6c 69 65 6e 74 2e 65 78 65 2c 63 72 6f 73 73 66 69 72 65 2e 65 78 65 2c 57 6f 77 2d 36 34 2e 65 78 65 } //01 00 
		$a_01_3 = {2f 6c 6f 76 65 2f } //00 00 
	condition:
		any of ($a_*)
 
}