
rule TrojanDownloader_O97M_Obfuse_PBD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 2e 44 61 74 } //1 S.Dat
		$a_01_1 = {3d 20 22 43 65 77 63 43 65 77 6d 43 65 77 64 2e 43 65 77 65 43 65 77 78 43 65 77 65 } //1 = "CewcCewmCewd.CeweCewxCewe
		$a_03_2 = {73 65 72 76 69 63 65 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 22 20 26 20 22 72 69 70 74 2e 53 68 90 02 10 65 6c 6c 22 2c 20 22 22 29 2e 52 75 6e 20 90 02 10 2c 20 30 90 00 } //1
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 90 02 10 2c 20 22 43 65 77 22 2c 20 22 22 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}