
rule TrojanDropper_O97M_Hancitor_IAT_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 68 69 28 6d 79 68 6f 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  Sub hi(myhome As String)
		$a_01_1 = {44 69 6d 20 67 6c 6f 67 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim glog As String
		$a_01_2 = {67 6c 6f 67 20 3d 20 57 6f 72 64 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //01 00  glog = Word.ActiveDocument.AttachedTemplate.Path
		$a_01_3 = {44 69 6d 20 68 73 61 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim hsa As String
		$a_01_4 = {68 73 61 20 3d 20 67 6c 6f 67 } //01 00  hsa = glog
		$a_01_5 = {46 75 6e 63 74 69 6f 6e 20 69 65 70 28 29 } //01 00  Function iep()
		$a_03_6 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 20 26 20 22 5c 57 30 22 20 26 20 22 72 22 20 26 20 22 64 2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c 22 29 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}