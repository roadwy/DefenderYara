
rule TrojanDropper_O97M_GraceWire_AN_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 56 42 41 37 20 41 6e 64 20 57 69 6e 36 34 20 54 68 65 6e } //1 #If VBA7 And Win64 Then
		$a_01_1 = {66 6f 72 6d 73 46 6f 6c 64 65 72 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 47 61 6c 6b 69 6e 56 61 5c 66 69 6c 65 73 5f 66 6f 72 5f 74 72 61 6e 73 70 6f 72 74 22 } //1 formsFolder = "C:\Users\GalkinVa\files_for_transport"
		$a_01_2 = {46 4d 4f 44 5f 45 72 5f 72 6f 2e 72 53 74 72 2e 69 6e 67 } //1 FMOD_Er_ro.rStr.ing
		$a_01_3 = {3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 26 } //1 = UserForm6.TextBox1.Tag &
		$a_01_4 = {55 6e 6c 6f 61 64 20 4d 2e 65 } //1 Unload M.e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}