
rule TrojanDropper_O97M_GraceWire_CO_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 5c 62 6f 6f 73 74 5f 74 68 72 65 61 64 22 } //1 ofbl = ofbl + "\boost_thread"
		$a_03_1 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 [0-10] 2e 78 6c 73 78 22 } //1
		$a_03_2 = {63 74 61 63 6b 50 75 70 20 3d 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-10] 22 } //1
		$a_01_3 = {54 65 78 74 42 6f 78 37 2e 53 65 6c 4c 65 6e 67 74 68 20 3d 20 54 65 78 74 42 6f 78 37 2e 54 65 78 74 4c 65 6e 67 74 68 } //1 TextBox7.SelLength = TextBox7.TextLength
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}