
rule TrojanDropper_O97M_GraceWire_CX_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 65 72 73 68 6c 65 70 20 3d 20 22 22 20 2b 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 dershlep = "" + Dialog4.TextBox1.Tag
		$a_01_1 = {6f 66 62 6c 20 3d 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //1 ofbl = Dialog4.TextBox3.Tag
		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2c 20 22 43 6f 70 79 22 20 2b 20 22 48 65 72 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 68 61 72 76 65 73 74 2e 49 74 65 6d 73 2e 49 74 65 6d 28 4c 72 69 67 61 74 29 } //1 CallByName DestinationKat, "Copy" + "Here", VbMethod, harvest.Items.Item(Lrigat)
		$a_01_3 = {45 6c 73 65 49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 4f 72 20 4e 6f 74 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 54 68 65 6e } //1 ElseIf tooolsetChunkI Or Not tooolsetChunkQ Then
		$a_01_4 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 44 72 69 76 65 29 } //1 CheckCar = car.SpecialFolders("" & Drive)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}