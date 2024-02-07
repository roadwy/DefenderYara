
rule TrojanDropper_O97M_Hancitor_HAD_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 67 6f 74 6f 64 6f 77 6e } //01 00  Call gotodown
		$a_01_1 = {57 30 72 64 2e 64 6c 6c } //01 00  W0rd.dll
		$a_01_2 = {79 61 2e 77 61 76 } //01 00  ya.wav
		$a_01_3 = {49 66 20 44 69 72 28 4c 65 66 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 2c 20 6e 74 67 73 29 20 26 20 22 4c 6f 63 22 20 26 20 22 61 6c 5c 54 65 22 20 26 20 22 6d 70 22 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e } //01 00  If Dir(Left(ActiveDocument.AttachedTemplate.Path, ntgs) & "Loc" & "al\Te" & "mp", vbDirectory) = "" Then
		$a_01_4 = {43 61 6c 6c 20 47 65 74 6d 65 28 4c 65 66 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 2c 20 6e 74 67 73 29 20 26 20 22 4c 6f 63 61 6c 5c 54 65 6d 70 22 29 } //01 00  Call Getme(Left(ActiveDocument.AttachedTemplate.Path, ntgs) & "Local\Temp")
		$a_01_5 = {53 65 6c 65 63 74 69 6f 6e 2e 54 79 70 65 42 61 63 6b 73 70 61 63 65 } //00 00  Selection.TypeBackspace
	condition:
		any of ($a_*)
 
}