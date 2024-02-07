
rule TrojanDropper_O97M_GraceWire_BY_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 6e 64 20 49 66 90 0c 02 00 4d 6f 64 75 6c 65 30 2e 57 75 7a 7a 79 42 75 64 20 38 30 30 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_1 = {63 20 3d 20 4d 69 2e 64 24 28 43 6f 6d 6d 61 2e 6e 64 24 2c 20 69 2c 20 31 29 } //01 00  c = Mi.d$(Comma.nd$, i, 1)
		$a_01_2 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 43 6f 6d 6d 61 2e 6e 64 24 29 } //01 00  For i = 1 To Len(Comma.nd$)
		$a_01_3 = {49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 6a 20 3d 20 43 6f 75 6e 74 20 41 6e 64 20 63 20 3c 3e 20 22 } //01 00  If tooolsetChunkI And j = Count And c <> "
		$a_01_4 = {49 66 20 72 65 73 75 6c 74 20 3d 20 52 43 50 4e 5f 44 5f 46 4d 4f 44 5f 4f 4b 20 54 68 65 6e } //01 00  If result = RCPN_D_FMOD_OK Then
		$a_01_5 = {6d 73 2e 67 52 2e 65 73 75 6c 74 20 3d 20 4d 73 67 42 6f 78 28 72 65 73 75 6c 74 20 26 20 22 29 20 22 29 } //00 00  ms.gR.esult = MsgBox(result & ") ")
	condition:
		any of ($a_*)
 
}