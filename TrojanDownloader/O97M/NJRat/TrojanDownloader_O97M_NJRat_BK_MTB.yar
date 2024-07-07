
rule TrojanDownloader_O97M_NJRat_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/NJRat.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 90 02 0f 2c 20 69 2c 20 32 29 29 20 2d 20 31 33 29 90 00 } //1
		$a_03_1 = {69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 0f 29 20 53 74 65 70 20 32 90 00 } //1
		$a_01_2 = {53 68 65 6c 6c 20 66 } //1 Shell f
		$a_01_3 = {53 75 62 20 73 61 64 73 61 64 28 29 } //1 Sub sadsad()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_NJRat_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/NJRat.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = CreateObject("Wscript.Shell")
		$a_01_1 = {57 51 44 57 51 45 57 51 45 57 51 2e 52 75 6e 20 61 73 64 } //1 WQDWQEWQEWQ.Run asd
		$a_01_2 = {4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 69 2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 69 2c 20 31 29 29 20 2d 20 6e 29 } //1 Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)
		$a_01_3 = {53 75 62 20 73 61 64 73 61 64 28 29 } //1 Sub sadsad()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}