
rule TrojanDropper_O97M_GraceWire_CJ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {45 6e 64 20 49 66 90 0c 02 00 4d 6f 64 75 6c 65 32 2e 57 75 7a 7a 79 42 75 64 20 33 39 30 30 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_03_1 = {44 65 72 54 69 70 90 0c 02 00 44 6f 45 76 65 6e 74 73 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_03_2 = {4b 69 6c 6c 20 4b 65 79 90 02 08 4e 65 78 74 20 4b 65 79 90 02 08 4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 30 90 00 } //01 00 
		$a_01_3 = {50 75 62 6c 69 63 20 53 75 62 20 57 75 7a 7a 79 42 75 64 28 64 49 6d 6d 65 72 20 41 73 20 49 6e 74 65 67 65 72 29 } //01 00  Public Sub WuzzyBud(dImmer As Integer)
		$a_01_4 = {63 20 3d 20 4d 69 2e 64 24 28 43 6f 6d 6d 61 2e 6e 64 24 2c 20 69 2c 20 31 29 } //01 00  c = Mi.d$(Comma.nd$, i, 1)
		$a_01_5 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 43 68 65 63 6b 43 61 72 28 63 61 72 20 41 73 20 4f 62 6a 65 63 74 2c 20 44 72 69 76 65 20 41 73 20 53 74 72 69 6e 67 29 } //00 00  Public Property Get CheckCar(car As Object, Drive As String)
	condition:
		any of ($a_*)
 
}