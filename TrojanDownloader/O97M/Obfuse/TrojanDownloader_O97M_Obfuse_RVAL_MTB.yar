
rule TrojanDownloader_O97M_Obfuse_RVAL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 69 64 28 65 6e 63 2c 20 69 69 69 6a 62 6a 68 76 62 64 68 62 76 68 73 64 68 67 62 73 64 66 69 2c 20 31 29 } //1 Mid(enc, iiijbjhvbdhbvhsdhgbsdfi, 1)
		$a_01_1 = {41 70 70 44 61 74 61 20 26 20 43 68 72 28 41 73 63 28 78 69 6b 68 6a 62 68 62 68 68 6b 75 62 6b 67 64 73 6a 62 6a 68 67 6a 67 78 29 20 2d 20 31 29 } //1 AppData & Chr(Asc(xikhjbhbhhkubkgdsjbjhgjgx) - 1)
		$a_01_2 = {3d 20 44 65 63 72 79 70 74 28 22 66 79 66 2f 6a 6a 6b 6a 22 29 } //1 = Decrypt("fyf/jjkj")
		$a_01_3 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Sub Workbook_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}