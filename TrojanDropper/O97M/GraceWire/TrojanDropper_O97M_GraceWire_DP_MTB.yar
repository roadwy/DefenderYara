
rule TrojanDropper_O97M_GraceWire_DP_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 43 68 65 63 6b 43 61 72 28 63 61 72 20 41 73 20 56 61 72 69 61 6e 74 2c 20 44 72 69 76 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  Public Property Get CheckCar(car As Variant, Drive As String)
		$a_01_1 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 44 72 69 76 65 29 } //01 00  CheckCar = car.SpecialFolders("" & Drive)
		$a_01_2 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 65 64 28 29 20 41 73 20 49 6e 74 65 67 65 72 } //01 00  Public Property Get Speed() As Integer
		$a_01_3 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 29 20 41 73 20 53 74 72 69 6e 67 } //01 00  Public Property Get SpecialFolders() As String
		$a_01_4 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 4c 65 74 20 4c 69 63 65 6e 73 65 50 6c 61 74 65 28 6c 70 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  Public Property Let LicensePlate(lp As String)
		$a_01_5 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 4c 65 74 20 53 70 65 65 64 28 73 70 20 41 73 20 49 6e 74 65 67 65 72 29 } //01 00  Public Property Let Speed(sp As Integer)
		$a_03_6 = {4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 90 0c 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}