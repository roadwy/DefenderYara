
rule TrojanDropper_O97M_Hancitor_JOAH_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOAH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 7a 6f 72 6f 2e 64 22 20 26 20 22 6f 63 } //01 00  \zoro.d" & "oc
		$a_01_1 = {44 69 6d 20 75 75 75 75 63 } //01 00  Dim uuuuc
		$a_01_2 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 53 75 62 66 6f 6c 64 65 72 73 5f 69 6e 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 22 4c 6f 63 22 20 26 20 22 22 20 26 20 22 61 22 20 26 20 66 6b 31 29 } //00 00  Call ThisDocument.Subfolders_in(Left(uuuuc, ntgs) & "Loc" & "" & "a" & fk1)
	condition:
		any of ($a_*)
 
}