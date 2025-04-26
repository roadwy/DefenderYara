
rule TrojanDropper_O97M_Hancitor_EOAD_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 66 66 66 66 20 3d 20 22 74 65 72 2e 64 22 } //1 fffff = "ter.d"
		$a_01_1 = {66 66 66 66 66 20 3d 20 66 66 66 66 66 20 26 20 22 6c 6c 22 } //1 fffff = fffff & "ll"
		$a_01_2 = {46 6f 72 20 45 61 63 68 20 4e 65 64 63 20 49 6e 20 6d 64 73 2e 53 75 62 46 6f 6c 64 65 72 73 } //1 For Each Nedc In mds.SubFolders
		$a_01_3 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 2c 20 6e 74 67 73 29 20 26 20 65 77 72 77 73 64 66 29 } //1 Call ThisDocument.hdhdd(Left(Options.DefaultFilePath(wdUserTemplatesPath), ntgs) & ewrwsdf)
		$a_01_4 = {4e 61 6d 65 20 70 61 66 73 20 41 73 20 70 6c 73 20 26 20 6f 78 6c } //1 Name pafs As pls & oxl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}