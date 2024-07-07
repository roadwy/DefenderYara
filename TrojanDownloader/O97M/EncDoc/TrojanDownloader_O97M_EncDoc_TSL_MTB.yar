
rule TrojanDownloader_O97M_EncDoc_TSL_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.TSL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 6d 6d 75 6c 71 75 72 61 6e 79 2e 6f 72 67 2f 62 76 61 6c 6c 64 68 7a 6e 2f } //1 http://ummulqurany.org/bvalldhzn/
		$a_01_1 = {43 3a 5c 54 65 73 74 5c 74 65 73 74 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //1 C:\Test\test2\Fiksat.exe
		$a_01_2 = {4f 70 65 6e 55 52 4c } //1 OpenURL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}