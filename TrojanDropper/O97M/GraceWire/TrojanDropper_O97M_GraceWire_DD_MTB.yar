
rule TrojanDropper_O97M_GraceWire_DD_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 43 68 65 63 6b 43 61 72 28 63 61 72 20 41 73 20 56 61 72 69 61 6e 74 2c 20 44 72 69 76 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Public Property Get CheckCar(car As Variant, Drive As String)
		$a_01_1 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 44 72 69 76 65 29 } //1 CheckCar = car.SpecialFolders("" & Drive)
		$a_01_2 = {44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 Dialog4.TextBox1.Tag
		$a_01_3 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 29 20 41 73 20 53 74 72 69 6e 67 } //1 Public Property Get SpecialFolders() As String
		$a_01_4 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 65 64 28 29 20 41 73 20 49 6e 74 65 67 65 72 } //1 Public Property Get Speed() As Integer
		$a_01_5 = {74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 3d 20 46 61 6c 73 65 } //1 tooolsetChunkI = False
		$a_01_6 = {74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 3d 20 54 72 75 65 } //1 tooolsetChunkI = True
		$a_01_7 = {49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 6a 20 3d 20 43 6f 75 6e 74 20 41 6e 64 20 63 } //1 If tooolsetChunkI And j = Count And c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}