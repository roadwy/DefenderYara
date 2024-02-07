
rule TrojanDropper_O97M_GraceWire_CR_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 44 69 72 20 28 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 29 } //01 00  ChDir (Dialog4.TextBox1.Tag)
		$a_01_1 = {44 69 6d 20 63 61 72 20 41 73 20 52 65 70 6f 73 69 74 6f 72 } //01 00  Dim car As Repositor
		$a_03_2 = {76 61 72 52 65 73 31 20 3d 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 43 41 4c 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 90 02 10 22 22 2c 22 22 4a 22 22 29 22 29 90 00 } //01 00 
		$a_03_3 = {45 6e 64 20 49 66 90 0c 02 00 4d 6f 64 75 6c 65 32 2e 57 75 7a 7a 79 42 75 64 20 33 39 30 30 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}