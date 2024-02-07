
rule TrojanDropper_O97M_GraceWire_CC_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 74 61 63 6b 50 75 70 20 3d 20 57 69 6e 64 6f 77 73 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b } //01 00  ctackPup = Windows.TextBox1.Tag +
		$a_03_1 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 90 02 08 2e 78 6c 73 78 22 90 00 } //01 00 
		$a_01_2 = {63 74 61 63 6b 50 6f 70 20 3d 20 64 65 72 73 68 6c 65 70 20 26 20 57 69 6e 64 6f 77 73 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 } //01 00  ctackPop = dershlep & Windows.TextBox3.Value
		$a_01_3 = {73 4f 66 62 6c 20 3d 20 22 22 22 22 20 2b } //01 00  sOfbl = """" +
		$a_01_4 = {56 69 73 74 61 51 20 63 74 61 63 6b 50 75 70 } //00 00  VistaQ ctackPup
	condition:
		any of ($a_*)
 
}