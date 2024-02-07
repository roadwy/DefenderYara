
rule TrojanDropper_O97M_GraceWire_BM_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 66 62 6c 20 3d 20 22 43 41 22 20 2b 20 22 4c 4c 28 22 22 22 20 2b 20 6f 66 62 6c } //01 00  ofbl = "CA" + "LL(""" + ofbl
		$a_01_1 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 6f 66 62 6c 20 26 20 22 22 22 2c 22 22 72 64 64 72 64 22 22 2c 22 22 4a 22 22 29 } //01 00  ExecuteExcel4Macro ofbl & """,""rddrd"",""J"")
		$a_01_2 = {3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 41 63 74 69 76 65 48 6f 74 62 69 74 2c 20 22 22 20 26 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 22 29 } //01 00  = car.CheckCar(ActiveHotbit, "" & K6GOAM.TextBox3.Tag + "")
		$a_01_3 = {43 68 44 69 72 20 28 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 29 } //00 00  ChDir (K6GOAM.TextBox1.Tag)
	condition:
		any of ($a_*)
 
}