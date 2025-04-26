
rule TrojanDropper_O97M_GraceWire_AS_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 4d 4f 44 5f 4f 4b } //1 FMOD_OK
		$a_01_1 = {6f 66 62 6c 20 3d 20 6f 66 62 6c 20 26 } //1 ofbl = ofbl &
		$a_01_2 = {2c 22 22 6c 61 64 6e 61 74 73 22 22 2c 22 22 4a 22 22 29 } //1 ,""ladnats"",""J"")
		$a_01_3 = {2e 6c 62 6c 53 63 68 6f 6f 6c 33 28 53 75 62 53 6c 69 70 43 6f 75 6e 74 29 20 3d 20 22 58 22 } //1 .lblSchool3(SubSlipCount) = "X"
		$a_01_4 = {2e 6c 62 6c 53 63 68 6f 6f 6c 31 28 69 29 20 3d 20 22 22 } //1 .lblSchool1(i) = ""
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}