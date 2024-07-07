
rule TrojanDropper_O97M_GraceWire_BQ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {63 74 61 63 6b 50 75 70 20 3d 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c 90 02 10 2e 78 6c 73 22 20 2b 20 22 78 22 90 00 } //1
		$a_01_1 = {63 74 61 63 6b 50 6f 70 20 3d 20 64 65 72 73 68 6c 65 70 20 26 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 } //1 ctackPop = dershlep & K6GOAM.TextBox3.Value
		$a_01_2 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 43 53 74 72 28 73 65 6e 64 69 6e 67 73 29 20 2b 20 22 2e 64 6c 6c 22 } //1 sOfbl = ofbl + CStr(sendings) + ".dll"
		$a_01_3 = {64 65 72 73 68 6c 65 70 20 3d 20 22 22 20 2b 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 dershlep = "" + K6GOAM.TextBox1.Tag
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}