
rule TrojanDropper_O97M_Hancitor_EOBF_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 66 6f 72 6d 2e 64 6f 63 } //01 00  reform.doc
		$a_01_1 = {66 61 66 61 61 20 3d 20 66 61 66 61 61 20 26 20 22 63 22 20 26 20 22 61 22 20 26 20 22 6c 22 } //01 00  fafaa = fafaa & "c" & "a" & "l"
		$a_01_2 = {66 61 66 61 61 20 3d 20 66 61 66 61 61 20 26 20 22 2f 22 20 26 20 22 54 65 6d 70 22 } //01 00  fafaa = fafaa & "/" & "Temp"
		$a_01_3 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 66 61 66 61 61 29 } //00 00  Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & fafaa)
	condition:
		any of ($a_*)
 
}