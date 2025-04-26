
rule TrojanDownloader_O97M_Obfuse_YB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 40 28 [0-08] 29 2e } //1
		$a_02_1 = {76 62 4e 65 77 4c 69 6e 65 20 26 20 [0-08] 28 28 57 53 63 72 69 70 74 2e 45 63 68 6f 28 29 } //1
		$a_00_2 = {41 31 3a 49 56 35 30 30 30 5d 2e 53 70 65 63 69 61 6c 43 65 6c 6c 73 28 78 6c 43 6f 6e 73 74 61 6e 74 73 29 } //1 A1:IV5000].SpecialCells(xlConstants)
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}