
rule TrojanDropper_O97M_Hancitor_RVD_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.RVD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 53 65 61 72 63 68 28 4d 79 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 61 29 2c 20 68 64 76 29 } //1 Call Search(MyFSO.GetFolder(asda), hdv)
		$a_01_1 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 65 77 72 77 73 64 66 29 } //1 Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & ewrwsdf)
		$a_01_2 = {6f 78 6c 20 3d 20 22 5c 67 6c 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 } //1 oxl = "\glib.d" & "o" & "c"
		$a_01_3 = {4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 } //1 Options.DefaultFilePath(wdUserTemplatesPath)
		$a_01_4 = {66 66 66 66 66 20 3d 20 22 67 6c 69 62 2e 62 22 20 26 20 22 61 78 22 } //1 fffff = "glib.b" & "ax"
		$a_01_5 = {2e 4f 70 65 6e 20 46 69 6c 65 4e 61 6d 65 3a 3d 76 63 62 63 20 26 20 22 5c 67 6c 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 } //1 .Open FileName:=vcbc & "\glib.d" & "o" & "c"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}