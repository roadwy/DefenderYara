
rule TrojanDropper_O97M_GraceWire_EA_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 20 3d 20 73 4e 4d 53 50 2e 4e 61 6d 65 73 70 61 63 65 28 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 29 } //1 Set DestinationKat = sNMSP.Namespace(Form0.TextBox3.Tag)
		$a_01_1 = {53 65 74 20 68 61 72 76 65 73 74 20 3d 20 73 4e 4d 53 50 2e 4e 61 6d 65 73 70 61 63 65 28 73 4f 66 62 6c 29 } //1 Set harvest = sNMSP.Namespace(sOfbl)
		$a_01_2 = {43 61 6c 6c 20 41 72 72 61 79 49 6e 73 65 72 74 28 62 2c 20 31 2c 20 66 73 6f 29 } //1 Call ArrayInsert(b, 1, fso)
		$a_01_3 = {44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2e 43 6f 70 79 48 65 72 65 20 68 61 72 76 65 73 74 2e 49 74 65 6d 73 2e 49 74 65 6d 28 4c 72 69 67 61 74 29 } //1 DestinationKat.CopyHere harvest.Items.Item(Lrigat)
		$a_01_4 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 65 64 28 29 20 41 73 20 49 6e 74 65 67 65 72 } //1 Public Property Get Speed() As Integer
		$a_01_5 = {50 75 62 6c 69 63 20 53 75 62 20 56 69 73 74 61 51 28 57 68 65 72 65 54 6f 47 6f 29 } //1 Public Sub VistaQ(WhereToGo)
		$a_03_6 = {46 6f 72 20 45 61 63 68 20 4b 65 79 20 49 6e 20 70 75 74 41 72 72 61 79 42 69 67 4c 69 73 74 [0-15] 4b 69 6c 6c 20 4b 65 79 [0-10] 4e 65 78 74 20 4b 65 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}