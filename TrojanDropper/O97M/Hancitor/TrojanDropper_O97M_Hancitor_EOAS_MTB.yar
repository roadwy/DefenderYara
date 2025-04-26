
rule TrojanDropper_O97M_Hancitor_EOAS_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOAS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 6f 75 73 78 } //1 Call ousx
		$a_01_1 = {44 69 6d 20 6f 78 6c } //1 Dim oxl
		$a_01_2 = {6f 78 6c 20 3d 20 22 5c 67 6c 69 62 2e 64 6f 63 22 } //1 oxl = "\glib.doc"
		$a_01_3 = {4e 61 6d 65 20 70 61 66 73 20 41 73 20 70 6c 73 20 26 20 6f 78 6c } //1 Name pafs As pls & oxl
		$a_01_4 = {43 61 6c 6c 20 75 6f 69 61 28 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 29 } //1 Call uoia(Options.DefaultFilePath(wdUserTemplatesPath))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}