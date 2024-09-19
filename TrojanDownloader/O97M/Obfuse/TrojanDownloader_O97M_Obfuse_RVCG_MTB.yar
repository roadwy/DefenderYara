
rule TrojanDownloader_O97M_Obfuse_RVCG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVCG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 72 65 76 65 6e 75 65 28 6d 61 72 67 69 6e 29 67 65 74 6f 62 6a 65 63 74 28 72 65 76 65 6e 75 65 28 22 31 34 36 31 33 32 31 33 37 31 33 36 31 33 30 31 33 36 31 34 33 31 34 32 30 38 35 22 29 29 } //1 =revenue(margin)getobject(revenue("146132137136130136143142085"))
		$a_01_1 = {3d 63 68 72 28 72 6f 69 2d 32 37 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 =chr(roi-27)endfunction
		$a_01_2 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 6d 79 6d 61 63 72 6f 65 6e 64 73 75 62 73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 document_open()mymacroendsubsubautoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}