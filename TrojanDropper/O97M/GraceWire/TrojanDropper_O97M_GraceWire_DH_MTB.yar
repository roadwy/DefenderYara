
rule TrojanDropper_O97M_GraceWire_DH_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 43 68 65 63 6b 43 61 72 28 63 61 72 20 41 73 20 56 61 72 69 61 6e 74 2c 20 44 72 69 76 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Public Property Get CheckCar(car As Variant, Drive As String)
		$a_01_1 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 44 72 69 76 65 29 } //1 CheckCar = car.SpecialFolders("" & Drive)
		$a_01_2 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 29 20 41 73 20 53 74 72 69 6e 67 } //1 Public Property Get SpecialFolders() As String
		$a_01_3 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 4c 65 74 20 4c 69 63 65 6e 73 65 50 6c 61 74 65 28 6c 70 20 41 73 20 53 74 72 69 6e 67 29 } //1 Public Property Let LicensePlate(lp As String)
		$a_01_4 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 65 64 28 29 20 41 73 20 49 6e 74 65 67 65 72 } //1 Public Property Get Speed() As Integer
		$a_03_5 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 32 39 31 30 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_03_6 = {44 6f 45 76 65 6e 74 73 90 0c 02 00 56 6f 6f 6f 6f 6f 68 65 61 64 90 0c 02 00 44 6f 45 76 65 6e 74 73 90 0c 02 00 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}