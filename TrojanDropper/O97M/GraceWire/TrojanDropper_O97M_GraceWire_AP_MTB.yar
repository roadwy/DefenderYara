
rule TrojanDropper_O97M_GraceWire_AP_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 4d 4f 44 } //01 00  FMOD
		$a_01_1 = {55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 3d 20 46 75 63 6a 69 46 69 6c 6d 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 29 } //01 00  UserForm6.TextBox3.Tag = FucjiFilm.SpecialFolders(UserForm6.TextBox3.Tag)
		$a_01_2 = {55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 3d 20 4b 6f 64 61 6b 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 29 } //01 00  UserForm6.TextBox3.Tag = Kodak.SpecialFolders("" & UserForm6.TextBox3.Tag)
		$a_01_3 = {55 6e 6c 6f 61 64 20 4d 2e 65 } //00 00  Unload M.e
	condition:
		any of ($a_*)
 
}