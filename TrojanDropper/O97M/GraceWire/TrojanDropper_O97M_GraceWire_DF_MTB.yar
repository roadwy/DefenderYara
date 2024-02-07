
rule TrojanDropper_O97M_GraceWire_DF_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 63 61 72 20 3d 20 4e 65 77 20 52 65 70 6f 73 69 74 6f 72 } //01 00  Set car = New Repositor
		$a_01_1 = {44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 54 53 50 49 50 2c 20 22 45 78 70 22 20 2b 20 22 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 50 52 50 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 25 22 29 } //01 00  Dialog4.TextBox1.Tag = CallByName(TSPIP, "Exp" + "andEnvironmentStrings", VbMethod, PRP + "" + "" + "%")
		$a_01_2 = {73 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 54 53 50 49 50 2c 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 26 20 22 22 29 } //01 00  s = car.CheckCar(TSPIP, Dialog4.TextBox3.ControlTipText & "")
		$a_01_3 = {44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 3d 20 73 } //01 00  Dialog4.TextBox3.Tag = s
		$a_01_4 = {4d 6f 64 75 6c 65 32 2e 57 75 7a 7a 79 42 75 64 20 33 39 30 30 } //00 00  Module2.WuzzyBud 3900
	condition:
		any of ($a_*)
 
}