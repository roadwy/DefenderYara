
rule TrojanDropper_O97M_GraceWire_AO_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {26 20 22 2e 64 90 02 06 6c 90 02 09 6c 22 90 00 } //1
		$a_03_1 = {3d 20 57 68 65 72 65 54 6f 47 6f 90 02 12 22 7a 90 02 09 69 90 02 09 70 90 00 } //1
		$a_01_2 = {55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //1 UserForm6.TextBox3.Tag
		$a_01_3 = {2c 20 46 4d 4f 44 5f } //1 , FMOD_
		$a_03_4 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 02 10 44 69 6d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}