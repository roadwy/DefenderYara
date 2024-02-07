
rule TrojanDropper_Linux_Bartallex_E{
	meta:
		description = "TrojanDropper:Linux/Bartallex.E,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 4c 65 66 74 28 22 77 69 6e 74 63 22 2c 20 33 29 20 26 20 22 6d 67 6d 74 73 22 20 26 20 52 69 67 68 74 28 22 74 65 74 72 61 67 6f 6e 3a 5c 5c 22 2c 20 33 29 } //01 00  = Left("wintc", 3) & "mgmts" & Right("tetragon:\\", 3)
		$a_00_1 = {26 20 22 6f 6f 74 22 20 2b 20 55 43 61 73 65 28 22 5c 63 69 6d 56 22 29 20 2b 20 22 32 22 } //01 00  & "oot" + UCase("\cimV") + "2"
		$a_00_2 = {3d 20 4c 43 61 73 65 28 22 77 69 4e 22 29 20 26 20 22 33 32 5f 50 72 6f 22 20 26 20 4c 43 61 73 65 28 22 43 65 53 73 22 29 } //01 00  = LCase("wiN") & "32_Pro" & LCase("CeSs")
		$a_00_3 = {46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 52 65 61 64 20 57 72 69 74 65 20 41 73 } //00 00  For Binary Access Read Write As
	condition:
		any of ($a_*)
 
}