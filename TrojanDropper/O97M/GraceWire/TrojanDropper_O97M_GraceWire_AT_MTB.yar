
rule TrojanDropper_O97M_GraceWire_AT_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 73 2e 67 52 2e 65 73 75 6c 74 20 3d 20 4d 73 67 42 6f 78 28 72 65 73 75 6c 74 20 26 20 22 29 20 22 20 26 20 46 4d 4f 44 5f 45 72 5f 72 6f 72 53 74 72 2e 69 6e 67 28 72 65 73 75 6c 74 29 29 } //01 00  ms.gR.esult = MsgBox(result & ") " & FMOD_Er_rorStr.ing(result))
		$a_01_1 = {46 69 6c 65 57 68 65 72 65 50 75 74 54 6f 32 2e 43 6f 70 79 48 65 72 65 20 46 69 6c 65 57 68 65 72 65 50 75 74 54 6f 2e 49 74 65 6d 73 2e 49 74 65 6d 28 55 73 65 72 46 6f 72 6d 36 2e 4c 61 62 65 6c 32 2e 54 61 67 29 } //01 00  FileWherePutTo2.CopyHere FileWherePutTo.Items.Item(UserForm6.Label2.Tag)
		$a_01_2 = {45 78 63 65 6c 2e 57 6f 72 6b 73 68 65 65 74 73 28 31 29 2e 52 61 6e 67 65 28 52 61 6e 67 65 29 } //01 00  Excel.Worksheets(1).Range(Range)
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 22 } //00 00  = CreateObject("Shell."
	condition:
		any of ($a_*)
 
}