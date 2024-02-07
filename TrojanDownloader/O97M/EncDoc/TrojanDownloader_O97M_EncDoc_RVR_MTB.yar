
rule TrojanDownloader_O97M_EncDoc_RVR_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 72 72 65 76 65 72 73 65 28 61 63 74 69 76 65 73 68 65 65 74 2e 72 61 6e 67 65 28 22 66 6b 31 35 36 22 29 2e 76 61 6c 75 65 29 } //01 00  strreverse(activesheet.range("fk156").value)
		$a_01_1 = {73 74 72 72 65 76 65 72 73 65 28 62 72 6a 6b 7a 6e 77 68 2b 76 76 69 7a 67 64 6b 7a 29 73 65 74 6c 63 72 74 64 62 70 3d 67 65 74 6f 62 6a 65 63 74 28 72 65 70 6c 61 63 65 28 22 77 69 73 68 31 74 73 68 31 74 74 79 6e 6d 67 73 68 31 74 73 68 31 74 74 79 6d 74 73 68 31 74 73 68 31 74 74 79 73 3a 5c 5c 2e 5c 72 6f 73 68 31 74 73 68 31 74 74 79 6f 74 } //01 00  strreverse(brjkznwh+vvizgdkz)setlcrtdbp=getobject(replace("wish1tsh1ttynmgsh1tsh1ttymtsh1tsh1ttys:\\.\rosh1tsh1ttyot
		$a_01_2 = {78 73 67 62 6f 61 6c 2e 6f 70 65 6e 22 67 65 74 22 2c 64 76 65 68 6b 64 6a 26 22 77 69 6e 64 6f 77 73 22 2c 66 61 6c 73 65 } //01 00  xsgboal.open"get",dvehkdj&"windows",false
		$a_01_3 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 79 79 6c 70 64 6c 7a 65 6e 64 73 75 62 } //00 00  document_open()yylpdlzendsub
	condition:
		any of ($a_*)
 
}