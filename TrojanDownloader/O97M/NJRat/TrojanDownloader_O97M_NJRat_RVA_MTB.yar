
rule TrojanDownloader_O97M_NJRat_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/NJRat.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 69 2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 69 2c 20 31 29 29 20 2d 20 6e 29 } //01 00  Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)
		$a_02_1 = {66 20 3d 20 78 73 61 64 77 71 64 77 71 64 28 90 01 0f 29 90 00 } //01 00 
		$a_00_2 = {53 68 65 6c 6c 20 66 } //01 00  Shell f
		$a_00_3 = {73 61 64 73 61 64 } //00 00  sadsad
	condition:
		any of ($a_*)
 
}