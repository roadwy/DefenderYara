
rule TrojanDropper_O97M_GraceWire_CP_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2c 20 22 43 6f 70 79 48 65 72 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 68 61 72 76 65 73 74 2e 49 74 65 6d 73 2e 49 74 65 6d 28 4c 72 69 67 61 74 29 } //1 CallByName DestinationKat, "CopyHere", VbMethod, harvest.Items.Item(Lrigat)
		$a_01_1 = {63 20 3d 20 4d 69 2e 64 24 28 43 6f 6d 6d 61 2e 6e 64 24 2c 20 69 2c 20 31 29 } //1 c = Mi.d$(Comma.nd$, i, 1)
		$a_01_2 = {73 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 72 65 64 6f 4d 6f 63 68 75 70 2c 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 26 20 22 22 29 } //1 s = car.CheckCar(redoMochup, Dialog4.TextBox3.ControlTipText & "")
		$a_01_3 = {73 20 3d 20 22 4d 61 6a 6f 72 20 68 65 61 6c 74 68 20 70 72 6f 62 6c 65 6d 73 22 } //1 s = "Major health problems"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}