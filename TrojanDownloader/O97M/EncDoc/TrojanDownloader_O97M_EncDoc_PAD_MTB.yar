
rule TrojanDownloader_O97M_EncDoc_PAD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 6f 63 50 61 74 68 20 3d 20 63 44 69 72 20 2b 20 22 5c 43 6f 76 69 64 20 47 75 69 64 65 6c 69 6e 65 73 2e 64 6f 63 22 } //1 docPath = cDir + "\Covid Guidelines.doc"
		$a_01_1 = {75 73 65 72 44 69 72 20 2b 20 22 5c 61 75 64 69 6f 64 6c 2e 65 78 65 27 3b 22 } //1 userDir + "\audiodl.exe';"
		$a_01_2 = {77 73 68 2e 65 78 65 63 20 28 64 4c 6f 61 64 29 } //1 wsh.exec (dLoad)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}