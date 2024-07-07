
rule TrojanDropper_O97M_GraceWire_CG_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 74 61 63 6b 50 69 70 20 3d 20 63 74 61 63 6b 50 75 70 20 26 20 50 61 67 65 31 31 2e 52 61 6e 67 65 28 22 41 31 31 35 22 29 2e 56 61 6c 75 65 } //1 ctackPip = ctackPup & Page11.Range("A115").Value
		$a_01_1 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 6f 66 62 6c 20 2b 20 22 2a 22 2c 20 63 74 61 63 6b 50 6f 70 2c 20 63 74 61 63 6b 50 69 70 } //1 PublicResumEraseByArrayList ofbl + "*", ctackPop, ctackPip
		$a_01_2 = {46 69 6c 65 43 6f 70 79 20 63 74 61 63 6b 50 75 70 2c 20 63 74 61 63 6b 50 69 70 } //1 FileCopy ctackPup, ctackPip
		$a_01_3 = {44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2e 43 6f 70 79 48 65 72 65 20 68 61 72 76 65 73 74 2e 49 74 65 6d 73 2e 49 74 65 6d 28 4c 72 69 67 61 74 29 } //1 DestinationKat.CopyHere harvest.Items.Item(Lrigat)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}