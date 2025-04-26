
rule TrojanDropper_O97M_Hancitor_AJ_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.AJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 } //1 Sub gotodown()
		$a_01_1 = {43 61 6c 6c 20 67 6f 74 6f 74 77 6f } //1 Call gototwo
		$a_01_2 = {49 66 20 44 69 72 28 70 61 66 68 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(pafh & "\W0rd.dll") = "" Then
		$a_01_3 = {49 66 20 44 69 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(ActiveDocument.AttachedTemplate.Path & "\W0rd.dll") = "" Then
		$a_01_4 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
		$a_01_5 = {46 6f 72 20 45 61 63 68 20 76 68 68 73 20 49 6e 20 66 6c 64 2e 53 55 42 46 4f 4c 44 45 52 53 } //1 For Each vhhs In fld.SUBFOLDERS
		$a_01_6 = {43 61 6c 6c 20 63 68 65 63 6b 74 68 65 28 61 66 73 29 } //1 Call checkthe(afs)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}