
rule TrojanDownloader_O97M_Hancitor_EOAI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Hancitor.EOAI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 71 2e 64 6f 63 22 2c } //01 00  qq.doc",
		$a_01_1 = {70 6c 73 20 3d 20 66 66 66 73 } //01 00  pls = fffs
		$a_01_2 = {49 66 20 44 69 72 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 65 77 72 77 73 64 66 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e } //01 00  If Dir(Left(uuuuc, ntgs) & ewrwsdf, vbDirectory) = "" Then
		$a_01_3 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 65 77 72 77 73 64 66 29 } //01 00  Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & ewrwsdf)
		$a_01_4 = {65 77 72 77 73 64 66 20 3d 20 22 4c 6f 63 61 6c 2f 54 65 6d 70 22 } //00 00  ewrwsdf = "Local/Temp"
	condition:
		any of ($a_*)
 
}