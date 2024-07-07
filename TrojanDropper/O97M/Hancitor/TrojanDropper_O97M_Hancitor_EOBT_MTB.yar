
rule TrojanDropper_O97M_Hancitor_EOBT_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 44 69 72 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 66 61 66 61 61 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(Left(uuuuc, ntgs) & fafaa, vbDirectory) = "" Then
		$a_01_1 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 66 61 66 61 61 29 } //1 Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & fafaa)
		$a_01_2 = {44 69 6d 20 6d 67 66 2c 20 75 68 6a 6b 6e 62 2c 20 77 65 72 73 2c 20 71 77 65 64 73 2c 20 66 61 66 61 61 20 41 73 20 53 74 72 69 6e 67 } //1 Dim mgf, uhjknb, wers, qweds, fafaa As String
		$a_01_3 = {44 69 6d 20 75 75 75 75 63 } //1 Dim uuuuc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}