
rule TrojanDropper_O97M_GraceWire_AX_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 22 } //1 .dll"
		$a_01_1 = {46 4d 4f 44 5f } //1 FMOD_
		$a_01_2 = {6f 66 62 6c 20 3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b } //1 ofbl = UserForm6.TextBox3.Tag +
		$a_01_3 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //1 .SpecialFolders("" & UserForm6.TextBox3.Tag
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}