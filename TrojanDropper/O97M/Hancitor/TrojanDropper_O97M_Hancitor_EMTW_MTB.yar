
rule TrojanDropper_O97M_Hancitor_EMTW_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMTW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 5c 75 72 69 70 2e 64 22 } //1 = "\urip.d"
		$a_01_1 = {49 66 20 44 69 72 28 6a 6f 73 20 26 20 22 5c 75 72 69 70 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(jos & "\urip.d" & "l" & "l") = "" Then
		$a_01_2 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 54 61 62 6c 65 73 28 31 29 2e 43 65 6c 6c 28 31 2c 20 31 29 2e 52 61 6e 67 65 2e 54 65 78 74 } //1 ThisDocument.Tables(1).Cell(1, 1).Range.Text
		$a_01_3 = {53 65 74 20 66 20 3d 20 66 73 2e 47 65 74 46 6f 6c 64 65 72 28 46 6f 6c 64 65 72 29 } //1 Set f = fs.GetFolder(Folder)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}