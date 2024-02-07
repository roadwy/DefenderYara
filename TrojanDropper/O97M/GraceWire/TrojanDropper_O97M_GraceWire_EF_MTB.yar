
rule TrojanDropper_O97M_GraceWire_EF_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 43 6f 70 79 20 53 72 63 20 26 20 22 5c 22 20 26 20 66 2c 20 44 73 74 20 26 20 22 5c 22 20 26 20 66 } //01 00  FileCopy Src & "\" & f, Dst & "\" & f
		$a_01_1 = {4f 50 61 74 68 20 3d 20 52 65 70 6c 61 63 65 28 54 72 69 6d 28 43 6f 6d 6d 61 6e 64 24 29 2c 20 22 22 22 22 2c 20 22 22 29 } //01 00  OPath = Replace(Trim(Command$), """", "")
		$a_01_2 = {74 61 72 67 65 74 45 58 45 20 3d 20 41 70 70 2e 70 61 74 68 20 26 20 22 5c 22 20 26 20 41 70 70 2e 45 58 45 4e 61 6d 65 20 26 20 22 2e 65 78 65 22 } //01 00  targetEXE = App.path & "\" & App.EXEName & ".exe"
		$a_01_3 = {74 65 6d 70 50 61 74 68 20 3d 20 56 42 41 2e 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 } //01 00  tempPath = VBA.Environ("temp")
		$a_01_4 = {63 74 61 63 6b 50 69 70 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 26 20 50 61 67 65 31 31 2e 52 61 6e 67 65 28 22 42 31 31 35 22 29 2e 76 61 6c 75 65 } //01 00  ctackPip = liquidOne & Page11.Range("B115").value
		$a_01_5 = {4c 72 69 67 61 74 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 31 2e 54 61 67 } //00 00  Lrigat = UserForm1.Label11.Tag
	condition:
		any of ($a_*)
 
}