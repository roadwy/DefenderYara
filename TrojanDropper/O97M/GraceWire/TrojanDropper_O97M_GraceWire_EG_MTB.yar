
rule TrojanDropper_O97M_GraceWire_EG_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c 61 63 61 64 65 6d 22 } //1 liquidOne = Form0.TextBox1.Tag + "\academ"
		$a_01_1 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 2b 20 22 6c 2e 78 6c 73 78 22 } //1 liquidOne = liquidOne + "l.xlsx"
		$a_01_2 = {6f 66 62 6c 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 ofbl = Form0.TextBox1.Tag
		$a_01_3 = {63 74 61 63 6b 50 69 70 2c 20 64 65 72 73 68 6c 65 70 20 26 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //1 ctackPip, dershlep & UserForm1.Label1.Tag
		$a_01_4 = {52 61 6e 67 65 28 22 44 32 22 29 2e 46 6f 72 6d 75 6c 61 20 3d 20 22 24 30 22 } //1 Range("D2").Formula = "$0"
		$a_01_5 = {2b 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //1 + Form0.TextBox3.Tag
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}