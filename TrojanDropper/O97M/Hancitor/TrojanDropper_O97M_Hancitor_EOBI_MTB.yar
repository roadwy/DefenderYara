
rule TrojanDropper_O97M_Hancitor_EOBI_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 65 66 6f 72 6d 2e 64 6f 63 } //1 reform.doc
		$a_01_1 = {66 61 66 61 61 20 3d 20 66 61 66 61 61 20 26 20 22 2f 22 } //1 fafaa = fafaa & "/"
		$a_01_2 = {66 61 66 61 61 20 3d 20 66 61 66 61 61 20 26 20 22 54 22 20 26 20 22 65 22 } //1 fafaa = fafaa & "T" & "e"
		$a_01_3 = {66 61 66 61 61 20 3d 20 66 61 66 61 61 20 26 20 22 6d 70 22 } //1 fafaa = fafaa & "mp"
		$a_01_4 = {44 69 6d 20 6b 75 6c 73 20 41 73 20 53 74 72 69 6e 67 } //1 Dim kuls As String
		$a_01_5 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 66 61 66 61 61 29 } //1 Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & fafaa)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}