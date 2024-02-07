
rule TrojanDropper_O97M_GraceWire_BJ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 43 61 72 20 3d 20 63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 22 20 2b 20 44 72 69 76 65 29 } //01 00  CheckCar = car.SpecialFolders("" + Drive)
		$a_01_1 = {76 53 70 65 65 64 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 6f 72 6b 73 68 65 65 74 46 75 6e 63 74 69 6f 6e 2e 4d 69 6e 28 73 70 2c 20 31 30 30 29 } //01 00  vSpeed = Application.WorksheetFunction.Min(sp, 100)
		$a_01_2 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 29 20 41 73 20 53 74 72 69 6e 67 } //01 00  Public Property Get SpecialFolders() As String
		$a_03_3 = {44 69 6d 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 73 20 42 6f 6f 6c 65 61 6e 90 02 08 44 69 6d 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 41 73 20 42 6f 6f 6c 65 61 6e 90 00 } //01 00 
		$a_01_4 = {46 4d 4f 44 5f 4f 4b 20 54 68 65 6e } //01 00  FMOD_OK Then
		$a_03_5 = {45 6e 64 20 49 66 90 02 04 4e 65 78 74 20 69 90 02 04 43 6c 6f 73 65 90 00 } //01 00 
		$a_01_6 = {49 74 65 6d 73 56 6c 6f 32 2e 43 6f 70 79 48 65 72 65 20 49 74 65 6d 73 56 6c 6f 2e 49 74 65 6d 73 2e 49 74 65 6d 28 } //00 00  ItemsVlo2.CopyHere ItemsVlo.Items.Item(
	condition:
		any of ($a_*)
 
}