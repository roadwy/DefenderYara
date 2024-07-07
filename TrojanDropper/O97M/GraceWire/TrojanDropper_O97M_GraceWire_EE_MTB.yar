
rule TrojanDropper_O97M_GraceWire_EE_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 74 61 63 6b 50 69 70 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 26 20 22 2e 7a 69 70 22 } //1 ctackPip = liquidOne & ".zip"
		$a_01_1 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 6f 66 62 6c 20 2b 20 22 2a 22 2c 20 63 74 61 63 6b 50 69 70 2c 20 64 65 72 73 68 6c 65 70 20 2b 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //1 PublicResumEraseByArrayList ofbl + "*", ctackPip, dershlep + UserForm1.Label1.Tag
		$a_01_2 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c 61 63 61 64 65 6d 22 } //1 liquidOne = Form0.TextBox1.Tag + "\academ"
		$a_01_3 = {76 61 72 32 62 69 6e 20 63 74 61 63 6b 50 69 70 20 2b 20 22 22 2c 20 64 61 74 61 } //1 var2bin ctackPip + "", data
		$a_01_4 = {67 67 67 2e 55 73 65 72 46 6f 72 6d 31 2e 48 69 64 65 } //1 ggg.UserForm1.Hide
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}