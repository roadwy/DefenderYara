
rule TrojanDropper_O97M_Hancitor_RVB_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 65 72 73 2e 4e 61 6d 65 20 3d 20 22 6b 69 6b 73 2e 64 6c 6c 22 } //1 Ters.Name = "kiks.dll"
		$a_01_1 = {64 66 62 76 63 20 3d 20 22 61 6c 22 20 26 20 22 5c 54 65 22 } //1 dfbvc = "al" & "\Te"
		$a_01_2 = {65 77 72 77 73 64 66 20 3d 20 22 4c 22 20 26 20 22 6f 22 20 26 20 22 63 22 20 26 20 64 66 62 76 63 20 26 20 22 6d 70 22 } //1 ewrwsdf = "L" & "o" & "c" & dfbvc & "mp"
		$a_01_3 = {6f 78 6c 20 3d 20 22 2e 64 6c 6c 22 } //1 oxl = ".dll"
		$a_03_4 = {4e 61 6d 65 20 70 61 66 73 20 41 73 20 70 6c 73 20 26 20 22 5c 90 02 06 6b 69 6b 75 73 22 20 26 20 6f 78 6c 90 00 } //1
		$a_01_5 = {43 61 6c 6c 20 75 6f 69 61 28 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 29 } //1 Call uoia(Options.DefaultFilePath(wdUserTemplatesPath))
		$a_01_6 = {45 61 63 68 20 4e 65 64 63 20 49 6e 20 6d 64 73 2e 53 75 62 46 6f 6c 64 65 72 73 } //1 Each Nedc In mds.SubFolders
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}