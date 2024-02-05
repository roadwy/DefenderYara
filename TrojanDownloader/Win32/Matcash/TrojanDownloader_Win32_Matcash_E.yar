
rule TrojanDownloader_Win32_Matcash_E{
	meta:
		description = "TrojanDownloader:Win32/Matcash.E,SIGNATURE_TYPE_PEHSTR,23 00 23 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 52 5c 6e 65 78 74 75 70 64 61 74 65 } //01 00 
		$a_01_1 = {57 52 5c 76 65 72 73 69 6f 6e } //01 00 
		$a_01_2 = {77 72 2e 6d 63 } //01 00 
		$a_01_3 = {2e 65 78 65 2e 74 6d 70 } //02 00 
		$a_01_4 = {70 61 69 64 } //0a 00 
		$a_01_5 = {61 66 66 49 44 } //0a 00 
		$a_01_6 = {66 69 6e 75 } //0a 00 
		$a_01_7 = {26 78 3d 00 26 69 3d 00 26 70 3d 00 26 63 6d 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}