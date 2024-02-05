
rule TrojanDownloader_Win32_Renos_LU{
	meta:
		description = "TrojanDownloader:Win32/Renos.LU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 61 6d 46 69 6c 65 73 44 69 72 00 } //01 00 
		$a_01_1 = {43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 00 } //01 00 
		$a_01_2 = {44 61 46 75 64 67 65 00 } //01 00 
		$a_01_3 = {73 65 74 75 70 2d 32 2e 31 31 2d 65 6e 67 2e 65 78 65 00 } //01 00 
		$a_01_4 = {75 70 64 61 74 65 2d 32 2e 31 31 2d 65 6e 67 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}