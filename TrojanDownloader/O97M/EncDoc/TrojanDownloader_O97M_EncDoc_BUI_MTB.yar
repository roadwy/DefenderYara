
rule TrojanDownloader_O97M_EncDoc_BUI_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.BUI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 76 6f 6f 70 65 6f 70 6c 65 2e 66 75 6e 2f 64 69 76 2f 34 34 33 37 36 } //1 http://voopeople.fun/div/44376
		$a_01_1 = {72 65 67 73 76 72 33 32 } //1 regsvr32
		$a_01_2 = {55 52 4c 4d 6f 6e } //1 URLMon
		$a_01_3 = {6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 ownloadToFileA
		$a_01_4 = {58 54 4f 57 4e 2e 64 6c 6c } //1 XTOWN.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}