
rule TrojanDropper_O97M_GraceWire_BS_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 52 50 20 3d 20 22 25 22 20 2b 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 PRP = "%" + K6GOAM.TextBox1.Tag
		$a_01_1 = {4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 3d 20 41 63 74 69 76 65 48 6f 74 62 69 74 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 50 52 50 20 2b 20 22 25 22 29 } //1 K6GOAM.TextBox1.Tag = ActiveHotbit.ExpandEnvironmentStrings(PRP + "%")
		$a_01_2 = {4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 41 63 74 69 76 65 48 6f 74 62 69 74 2c 20 22 22 20 26 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 26 20 22 22 29 } //1 K6GOAM.TextBox3.Tag = car.CheckCar(ActiveHotbit, "" & K6GOAM.TextBox3.Tag & "")
		$a_01_3 = {53 65 74 20 63 61 72 20 3d 20 4e 65 77 20 43 61 72 43 6c 61 73 73 } //1 Set car = New CarClass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}