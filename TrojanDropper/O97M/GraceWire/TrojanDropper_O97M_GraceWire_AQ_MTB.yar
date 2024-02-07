
rule TrojanDropper_O97M_GraceWire_AQ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 62 75 69 6c 64 50 61 74 68 46 6f 72 20 2b 20 22 5c 6f 6c 65 22 20 2b 20 22 4f 62 6a 22 20 2b 20 22 65 63 74 2a } //01 00  = buildPathFor + "\ole" + "Obj" + "ect*
		$a_01_1 = {57 68 65 72 65 54 6f 47 6f 20 3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 26 20 22 5c 70 72 6f 70 65 72 74 79 22 20 2b 20 22 2e 78 6c 73 } //01 00  WhereToGo = UserForm6.TextBox1.Tag & "\property" + ".xls
		$a_01_2 = {55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 26 20 22 5c 72 65 70 6f 73 69 74 6f 72 79 22 20 2b 20 22 2e 78 6c 73 } //01 00  UserForm6.TextBox1.Tag & "\repository" + ".xls
		$a_01_3 = {2b 20 22 7a 69 22 20 2b 20 22 70 22 } //00 00  + "zi" + "p"
	condition:
		any of ($a_*)
 
}