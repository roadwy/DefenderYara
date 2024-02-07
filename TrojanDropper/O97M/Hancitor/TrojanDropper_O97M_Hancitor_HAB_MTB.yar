
rule TrojanDropper_O97M_Hancitor_HAB_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 73 64 66 20 3d 20 52 6f 6f 74 50 61 74 68 } //01 00  asdf = RootPath
		$a_01_1 = {26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //01 00  & "\W0rd.dll") = "" Then
		$a_03_2 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 08 20 26 20 22 70 22 20 26 20 22 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 22 20 26 20 22 4f 62 6a 65 63 74 22 29 90 00 } //01 00 
		$a_01_3 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00  Set fld = fso.GetFolder(asdf)
		$a_01_4 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c 79 61 2e 77 61 76 22 29 } //01 00  strFileExists = Dir(RootPath & "\ya.wav")
		$a_01_5 = {46 6f 72 20 45 61 63 68 20 76 68 68 73 20 49 6e 20 66 6c 64 2e 53 55 42 46 4f 4c 44 45 52 53 } //00 00  For Each vhhs In fld.SUBFOLDERS
	condition:
		any of ($a_*)
 
}