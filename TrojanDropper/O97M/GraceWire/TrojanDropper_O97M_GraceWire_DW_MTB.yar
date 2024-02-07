
rule TrojanDropper_O97M_GraceWire_DW_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6d 70 6f 73 69 74 69 6f 6e 20 64 65 72 73 68 6c 65 70 20 2b 20 22 22 20 2b 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 20 2b 20 22 22 20 26 20 22 22 2c 20 73 4f 66 62 6c 2c 20 4e 75 6d 42 46 6f 72 52 65 61 64 } //01 00  Composition dershlep + "" + UserForm1.Label1.Tag + "" & "", sOfbl, NumBForRead
		$a_01_1 = {53 65 74 20 44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 20 3d 20 73 4e 4d 53 50 2e 4e 61 6d 65 73 70 61 63 65 28 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 29 } //01 00  Set DestinationKat = sNMSP.Namespace(Form0.TextBox3.Tag)
		$a_01_2 = {44 69 6d 20 63 61 72 20 41 73 20 4c 75 6d 65 6e 65 } //01 00  Dim car As Lumene
		$a_01_3 = {44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2e 43 6f 70 79 48 65 72 65 20 68 61 72 76 65 73 74 2e 49 74 65 6d 73 2e 49 74 65 6d 28 4c 72 69 67 61 74 29 } //01 00  DestinationKat.CopyHere harvest.Items.Item(Lrigat)
		$a_01_4 = {73 65 74 44 4c 4c 44 69 72 65 63 74 6f 72 79 20 22 22 20 2b 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //01 00  setDLLDirectory "" + Form0.TextBox3.Tag
		$a_01_5 = {56 69 73 74 61 51 20 6c 69 71 75 69 64 4f 6e 65 } //00 00  VistaQ liquidOne
	condition:
		any of ($a_*)
 
}