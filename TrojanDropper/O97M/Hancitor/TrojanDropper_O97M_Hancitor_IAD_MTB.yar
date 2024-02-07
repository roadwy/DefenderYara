
rule TrojanDropper_O97M_Hancitor_IAD_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 68 69 28 6d 79 68 6f 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  Sub hi(myhome As String)
		$a_01_1 = {44 69 6d 20 67 6c 6f 67 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim glog As String
		$a_01_2 = {67 6c 6f 67 20 3d 20 72 65 70 69 64 } //01 00  glog = repid
		$a_01_3 = {44 69 6d 20 68 73 61 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim hsa As String
		$a_01_4 = {68 73 61 20 3d 20 67 6c 6f 67 } //01 00  hsa = glog
		$a_01_5 = {44 69 6d 20 6a 73 64 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim jsd As String
		$a_01_6 = {44 69 6d 20 70 75 73 68 73 74 72 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim pushstr As String
		$a_03_7 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 20 26 20 22 5c 57 30 22 20 26 20 22 72 64 2e 64 6c 6c 22 29 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}