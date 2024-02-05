
rule TrojanDownloader_O97M_Powdow_RVBY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 5f 73 68 65 6c 6c 21 5f 28 78 78 78 78 78 78 78 78 78 78 6c 6f 72 61 29 65 6e 64 73 75 62 } //01 00 
		$a_01_1 = {78 78 78 78 78 78 78 78 78 78 6c 6f 72 61 5f 3d 62 75 62 75 2e 62 75 62 75 2e 76 61 6c 75 65 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 64 65 62 75 67 5f 2e 5f 70 72 69 6e 74 } //01 00 
		$a_01_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } //00 00 
	condition:
		any of ($a_*)
 
}