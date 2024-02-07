
rule TrojanDropper_O97M_GraceWire_BZ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 52 50 20 3d 20 22 25 22 20 2b 20 57 69 6e 64 6f 77 73 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //01 00  PRP = "%" + Windows.TextBox1.Tag
		$a_01_1 = {57 69 6e 64 6f 77 73 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 3d 20 41 63 74 69 76 65 48 6f 74 62 69 74 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 50 52 50 20 2b 20 22 25 22 29 } //01 00  Windows.TextBox1.Tag = ActiveHotbit.ExpandEnvironmentStrings(PRP + "%")
		$a_01_2 = {57 69 6e 64 6f 77 73 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 41 63 74 69 76 65 48 6f 74 62 69 74 2c 20 57 69 6e 64 6f 77 73 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 26 20 22 22 29 } //00 00  Windows.TextBox3.Tag = car.CheckCar(ActiveHotbit, Windows.TextBox3.Tag & "")
	condition:
		any of ($a_*)
 
}