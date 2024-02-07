
rule TrojanDownloader_O97M_Gamaredon_AA{
	meta:
		description = "TrojanDownloader:O97M/Gamaredon.AA,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 22 68 74 74 70 3a 2f 2f 77 69 66 63 2e 77 65 62 73 69 74 65 2f 22 20 26 20 90 02 20 20 26 20 22 5f 22 20 26 20 48 65 78 28 90 02 20 29 20 26 20 22 2f 45 78 65 6c 43 72 65 61 74 65 5f 76 2e 90 02 20 2e 73 6d 73 22 90 00 } //01 00 
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 } //00 00  = Environ("temp")
	condition:
		any of ($a_*)
 
}