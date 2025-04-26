
rule TrojanDropper_O97M_GraceWire_EO_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 2e 7a 69 70 22 } //1 sOfbl = ofbl + ".zip"
		$a_01_1 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 6f 66 62 6c 20 2b 20 22 2a 22 2c 20 63 74 61 63 6b 50 69 70 2c 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c 6c 69 62 52 65 71 2a 22 2c 20 73 4f 66 62 6c 2c 20 64 65 72 73 68 6c 65 70 20 26 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //1 PublicResumEraseByArrayList ofbl + "*", ctackPip, Form0.TextBox3.Tag + "\libReq*", sOfbl, dershlep & UserForm1.Label1.Tag
		$a_01_2 = {46 69 6c 65 43 6f 70 79 20 53 6f 75 72 63 65 3a 3d 6c 69 71 75 69 64 4f 6e 65 2c 20 44 65 73 74 69 6e 61 74 69 6f 6e 3a 3d 63 74 61 63 6b 50 69 70 } //1 FileCopy Source:=liquidOne, Destination:=ctackPip
		$a_01_3 = {4c 72 69 67 61 74 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 31 2e 43 61 70 74 69 6f 6e } //1 Lrigat = UserForm1.Label11.Caption
		$a_01_4 = {52 61 6e 67 65 28 22 41 32 22 29 2e 46 6f 72 6d 75 6c 61 20 3d 20 22 24 30 22 } //1 Range("A2").Formula = "$0"
		$a_01_5 = {43 6f 6d 70 6f 73 69 74 69 6f 6e 20 64 65 72 73 68 6c 65 70 20 2b 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 20 2b 20 22 22 20 26 20 22 22 2c 20 73 4f 66 62 6c 2c 20 4e 75 6d 42 46 6f 72 52 65 61 64 } //1 Composition dershlep + UserForm1.Label1.Tag + "" & "", sOfbl, NumBForRead
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}