
rule TrojanDownloader_O97M_EncDoc_PAF_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 6e 65 77 6d 61 63 72 6f 73 22 73 75 62 } //01 00  vb_name="newmacros"sub
		$a_03_1 = {29 29 2e 63 72 65 61 74 65 90 02 1f 2c 6e 75 6c 6c 2c 6e 75 6c 6c 2c 70 69 64 65 6e 64 73 75 62 73 75 62 90 00 } //01 00 
		$a_03_2 = {3d 31 74 6f 6c 65 6e 28 90 02 0f 29 73 74 65 70 32 90 02 0f 3d 90 1b 01 26 63 68 72 24 28 76 61 6c 28 22 26 68 22 26 6d 69 64 24 28 90 1b 00 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}