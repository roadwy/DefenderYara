
rule TrojanDropper_O97M_GraceWire_DN_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 42 54 20 3d 20 54 42 54 20 2b 20 22 25 22 } //01 00  TBT = TBT + "%"
		$a_01_1 = {54 42 54 20 3d 20 54 53 50 49 50 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 54 42 54 29 } //01 00  TBT = TSPIP.ExpandEnvironmentStrings(TBT)
		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2c 20 22 54 61 67 22 2c 20 56 62 4c 65 74 2c 20 54 42 54 } //01 00  CallByName Form0.TextBox1, "Tag", VbLet, TBT
		$a_01_3 = {73 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 54 53 50 49 50 2c 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 26 20 22 22 29 } //01 00  s = car.CheckCar(TSPIP, Form0.TextBox3.ControlTipText & "")
		$a_01_4 = {50 52 50 20 3d 20 22 25 22 20 26 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //00 00  PRP = "%" & Form0.TextBox1.Tag
	condition:
		any of ($a_*)
 
}