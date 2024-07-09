
rule TrojanDropper_O97M_IcedID_PKE_MTB{
	meta:
		description = "TrojanDropper:O97M/IcedID.PKE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 70 6c 69 74 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 67 65 74 53 2c 20 22 7c 22 29 } //1 = Split(ThisDocument.getS, "|")
		$a_03_1 = {63 4f 62 6a 65 63 74 28 [0-20] 28 30 29 20 2b 20 22 2e 22 20 2b 20 [0-20] 28 31 29 29 2e 65 78 65 63 20 [0-20] 28 32 29 20 2b 20 22 20 22 20 2b } //1
		$a_01_2 = {70 31 2e 46 69 6e 64 2e 54 65 78 74 20 3d 20 22 31 34 5f 6b 22 } //1 p1.Find.Text = "14_k"
		$a_01_3 = {70 31 2e 46 69 6e 64 2e 52 65 70 6c 61 63 65 6d 65 6e 74 2e 54 65 78 74 20 3d 20 22 22 } //1 p1.Find.Replacement.Text = ""
		$a_01_4 = {70 31 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c } //1 p1.Find.Execute Replace:=wdReplaceAll
		$a_03_5 = {3d 20 54 72 69 6d 28 22 [0-20] 2e 68 22 20 26 20 [0-20] 28 33 29 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}