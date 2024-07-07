
rule TrojanDownloader_O97M_EncDoc_STL_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 69 6d 20 61 20 41 73 20 4e 65 77 20 53 63 72 69 70 74 43 6f 6e 74 72 6f 6c } //1 Dim a As New ScriptControl
		$a_01_1 = {61 2e 4c 61 6e 67 75 61 67 65 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 53 75 62 6a 65 63 74 22 29 2e 56 61 6c 75 65 } //1 a.Language = ActiveWorkbook.BuiltinDocumentProperties("Subject").Value
		$a_03_2 = {61 2e 41 64 64 43 6f 64 65 20 28 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 2e 56 61 6c 75 65 29 90 02 03 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}