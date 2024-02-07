
rule TrojanDownloader_O97M_Obfuse_CV{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CV,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 77 28 90 02 10 29 90 00 } //0a 00 
		$a_01_1 = {3d 20 22 53 48 45 22 20 26 20 22 4c 4c 20 22 } //01 00  = "SHE" & "LL "
		$a_03_2 = {43 61 6c 6c 20 90 02 10 28 90 02 10 20 26 90 00 } //01 00 
		$a_01_3 = {3d 20 22 6f 77 22 } //01 00  = "ow"
		$a_03_4 = {44 69 6d 20 90 02 10 28 90 10 03 00 20 54 6f 20 90 10 03 00 29 20 41 73 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}