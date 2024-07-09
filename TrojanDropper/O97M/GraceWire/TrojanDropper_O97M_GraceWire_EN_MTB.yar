
rule TrojanDropper_O97M_GraceWire_EN_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 74 61 63 6b 50 69 70 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 26 20 22 2e 7a 69 70 22 } //1 ctackPip = liquidOne & ".zip"
		$a_01_1 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c 61 63 61 64 65 6d 22 } //1 liquidOne = Form0.TextBox1.Tag + "\academ"
		$a_01_2 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 2b 20 22 6c 2e 78 6c 73 78 22 } //1 liquidOne = liquidOne + "l.xlsx"
		$a_01_3 = {6f 66 62 6c 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 ofbl = Form0.TextBox1.Tag
		$a_01_4 = {6f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 5c 6c 69 62 52 65 71 22 } //1 ofbl = ofbl + "\libReq"
		$a_03_5 = {50 75 62 6c 69 63 20 53 75 62 20 56 69 73 74 61 51 28 57 68 65 72 65 54 6f 47 6f 29 [0-04] 44 6f 45 76 65 6e 74 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}