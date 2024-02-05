
rule TrojanDownloader_O97M_EncDoc_SMP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SMP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 31 30 36 2c 20 32 29 2c 20 22 52 70 63 65 } //01 00 
		$a_00_1 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 31 30 37 2c 20 32 29 2c 20 22 52 70 63 65 } //01 00 
		$a_00_2 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 31 30 38 2c 20 32 29 2c 20 22 52 70 63 65 } //01 00 
		$a_00_3 = {3c 3e 20 22 62 68 63 6b 6c 61 22 20 54 68 65 6e } //01 00 
		$a_00_4 = {66 69 72 73 74 41 64 64 72 65 73 73 20 3d 20 22 33 34 6b 6c 61 22 } //00 00 
	condition:
		any of ($a_*)
 
}