
rule TrojanDropper_O97M_Hancitor_JOAI_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOAI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 61 6d 65 20 6d 79 46 69 6c 65 2e 70 61 74 68 20 41 73 20 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 20 26 20 22 5c 7a 6f 72 6f 2e 64 6f 63 } //1 Name myFile.path As Options.DefaultFilePath(wdUserTemplatesPath) & "\zoro.doc
		$a_01_1 = {43 61 6c 6c 20 70 70 70 78 } //1 Call pppx
		$a_01_2 = {53 65 74 20 6d 79 46 6f 6c 64 65 72 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 6d 79 50 61 74 68 29 } //1 Set myFolder = fso.GetFolder(myPath)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}