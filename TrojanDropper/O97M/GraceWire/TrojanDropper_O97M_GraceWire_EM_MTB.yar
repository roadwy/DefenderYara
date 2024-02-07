
rule TrojanDropper_O97M_GraceWire_EM_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 43 68 65 63 6b 43 61 72 28 63 61 72 20 41 73 20 56 61 72 69 61 6e 74 2c 20 44 72 69 76 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  Public Property Get CheckCar(car As Variant, Drive As String)
		$a_01_1 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 26 20 44 72 69 76 65 29 } //01 00  CheckCar = car.SpecialFolders("" & Drive)
		$a_01_2 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 29 20 41 73 20 53 74 72 69 6e 67 } //01 00  Public Property Get SpecialFolders() As String
		$a_01_3 = {4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 } //01 00  LicensePlate = vLicensePlate
		$a_01_4 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 4c 65 74 20 4c 69 63 65 6e 73 65 50 6c 61 74 65 28 6c 70 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  Public Property Let LicensePlate(lp As String)
		$a_01_5 = {49 66 20 4c 65 6e 28 6c 70 29 20 3c 3e 20 36 20 54 68 65 6e 20 45 72 72 2e 52 61 69 73 65 20 28 78 6c 45 72 72 56 61 6c 75 65 29 } //01 00  If Len(lp) <> 6 Then Err.Raise (xlErrValue)
		$a_01_6 = {76 4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 6c 70 } //01 00  vLicensePlate = lp
		$a_01_7 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 65 64 28 29 20 41 73 20 49 6e 74 65 67 65 72 } //01 00  Public Property Get Speed() As Integer
		$a_01_8 = {53 70 65 65 64 20 3d 20 76 53 70 65 65 64 } //01 00  Speed = vSpeed
		$a_01_9 = {73 4f 66 62 6c 20 3d 20 22 22 22 22 20 2b 20 73 4f 66 62 6c 20 26 20 22 22 22 2c 22 22 22 } //01 00  sOfbl = """" + sOfbl & ""","""
		$a_01_10 = {74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 3d 20 46 61 6c 73 65 } //01 00  tooolsetChunkI = False
		$a_01_11 = {74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 3d 20 46 61 6c 73 65 } //01 00  tooolsetChunkQ = False
		$a_03_12 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_13 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 52 65 64 42 75 74 74 6f 6e 28 64 49 6d 6d 65 72 20 41 73 20 44 6f 75 62 6c 65 29 } //00 00  Public Function RedButton(dImmer As Double)
	condition:
		any of ($a_*)
 
}