
rule TrojanDropper_O97M_Hancitor_JOAF_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOAF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 7a 6f 72 6f 2e 64 6f 63 } //01 00  \zoro.doc
		$a_01_1 = {43 61 6c 6c 20 50 72 69 6d 65 72 31 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 22 5c 4c 6f 63 61 6c 5c 22 20 26 20 22 54 65 6d 70 22 29 } //01 00  Call Primer1(Left(uuuuc, ntgs) & "\Local\" & "Temp")
		$a_01_2 = {75 75 75 75 63 20 3d 20 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 } //01 00  uuuuc = Options.DefaultFilePath(wdUserTemplatesPath
		$a_01_3 = {43 61 6c 6c 20 70 70 70 78 } //00 00  Call pppx
	condition:
		any of ($a_*)
 
}