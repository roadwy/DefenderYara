
rule TrojanDropper_O97M_GraceWire_EJ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 2e 7a 69 70 22 } //01 00  sOfbl = ofbl + ".zip"
		$a_01_1 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 6f 66 62 6c 20 2b 20 22 2a 22 2c 20 73 4f 66 62 6c 2c 20 63 74 61 63 6b 50 69 70 2c 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c 6c 69 62 52 65 71 2a 22 2c 20 64 65 72 73 68 6c 65 70 20 26 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //01 00  PublicResumEraseByArrayList ofbl + "*", sOfbl, ctackPip, Form0.TextBox3.Tag + "\libReq*", dershlep & UserForm1.Label1.Tag
		$a_01_2 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 2b 20 22 6c 2e 78 6c 73 78 22 } //01 00  liquidOne = liquidOne + "l.xlsx"
		$a_01_3 = {6f 66 62 6c 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //00 00  ofbl = Form0.TextBox1.Tag
	condition:
		any of ($a_*)
 
}