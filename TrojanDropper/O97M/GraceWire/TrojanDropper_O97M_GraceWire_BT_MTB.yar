
rule TrojanDropper_O97M_GraceWire_BT_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 63 74 61 63 6b 50 6f 70 2c 20 6f 66 62 6c 2c 20 63 74 61 63 6b 50 69 70 } //1 PublicResumEraseByArrayList ctackPop, ofbl, ctackPip
		$a_03_1 = {49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 6a 20 3d 20 43 6f 75 6e 74 20 41 6e 64 20 63 20 3c 3e 20 22 22 22 22 20 54 68 65 6e 20 47 65 74 50 2e 61 72 61 6d 20 3d 20 47 65 74 50 2e 61 72 61 6d 20 26 20 63 [0-10] 4e 65 78 74 20 69 } //1
		$a_01_2 = {63 20 3d 20 4d 69 2e 64 24 28 43 6f 6d 6d 61 2e 6e 64 24 2c 20 69 2c 20 31 29 } //1 c = Mi.d$(Comma.nd$, i, 1)
		$a_01_3 = {49 66 20 72 65 73 75 6c 74 20 3d 20 52 43 50 4e 5f 44 5f 46 4d 4f 44 5f 4f 4b 20 54 68 65 6e } //1 If result = RCPN_D_FMOD_OK Then
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}