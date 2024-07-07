
rule TrojanDropper_O97M_GraceWire_DA_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 74 61 63 6b 50 69 70 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 26 20 50 61 67 65 31 31 2e 52 61 6e 67 65 28 22 42 31 31 35 22 29 2e 56 61 6c 75 65 } //1 ctackPip = liquidOne & Page11.Range("B115").Value
		$a_01_1 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 6f 66 62 6c 20 2b 20 22 2a 22 2c 20 63 74 61 63 6b 50 69 70 2c 20 64 65 72 73 68 6c 65 70 20 2b 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //1 PublicResumEraseByArrayList ofbl + "*", ctackPip, dershlep + UserForm1.Label1.Tag
		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2c 20 22 43 6f 70 79 22 20 2b 20 22 48 65 72 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 68 61 72 76 65 73 74 2e 49 74 65 6d 73 2e 49 74 65 6d 28 4c 72 69 67 61 74 29 } //1 CallByName DestinationKat, "Copy" + "Here", VbMethod, harvest.Items.Item(Lrigat)
		$a_01_3 = {43 61 6c 6c 42 79 4e 61 6d 65 20 44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2c 20 22 43 6f 22 20 2b 20 22 70 79 22 20 2b 20 22 48 65 72 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 68 61 72 76 65 73 74 2e 49 74 65 6d 73 2e 49 74 65 6d 28 4c 72 69 67 61 74 29 } //1 CallByName DestinationKat, "Co" + "py" + "Here", VbMethod, harvest.Items.Item(Lrigat)
		$a_01_4 = {6f 66 62 6c 20 3d 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //1 ofbl = Dialog4.TextBox3.Tag
		$a_01_5 = {6f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 5c 73 72 74 5f 6a 6f 69 6e } //1 ofbl = ofbl + "\srt_join
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}