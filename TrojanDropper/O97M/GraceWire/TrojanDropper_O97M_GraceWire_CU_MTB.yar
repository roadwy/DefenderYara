
rule TrojanDropper_O97M_GraceWire_CU_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 90 02 08 2e 78 6c 73 78 22 90 00 } //1
		$a_03_1 = {63 74 61 63 6b 50 69 70 20 3d 20 63 74 61 63 6b 50 75 70 20 26 20 50 61 67 65 31 31 2e 52 61 6e 67 65 28 22 90 02 10 22 29 2e 56 61 6c 75 65 90 00 } //1
		$a_01_2 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 6f 66 62 6c 20 2b 20 22 2a 22 2c 20 63 74 61 63 6b 50 69 70 2c 20 64 65 72 73 68 6c 65 70 20 2b 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } //1 PublicResumEraseByArrayList ofbl + "*", ctackPip, dershlep + UserForm1.Label1.Tag
		$a_01_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 48 69 64 64 65 6e 45 45 34 4d 28 73 4f 66 62 6c 29 } //1 Public Function HiddenEE4M(sOfbl)
		$a_01_4 = {48 69 64 64 65 6e 45 45 34 4d 20 3d 20 46 61 6c 73 65 } //1 HiddenEE4M = False
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}