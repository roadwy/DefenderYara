
rule TrojanDropper_O97M_GraceWire_DK_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {64 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 45 78 63 65 6c 43 2c 20 22 45 78 65 63 75 22 20 2b 20 22 74 65 45 22 20 2b 20 22 78 63 65 6c 34 4d 61 63 72 6f 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 43 41 4c 22 20 2b 20 22 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 90 02 10 22 22 2c 22 22 4a 22 22 29 22 29 90 00 } //1
		$a_01_1 = {63 74 61 63 6b 50 69 70 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 26 20 50 61 67 65 31 31 2e 52 61 6e 67 65 28 22 42 31 31 35 22 29 2e 56 61 6c 75 65 } //1 ctackPip = liquidOne & Page11.Range("B115").Value
		$a_01_2 = {55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 31 2e 54 61 67 } //1 UserForm1.Label11.Tag
		$a_01_3 = {53 65 74 20 68 61 72 76 65 73 74 20 3d 20 73 4e 4d 53 50 2e 4e 61 6d 65 73 70 61 63 65 28 63 74 61 63 6b 50 69 70 29 } //1 Set harvest = sNMSP.Namespace(ctackPip)
		$a_01_4 = {43 61 6c 6c 42 79 4e 61 6d 65 20 44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2c 20 22 43 6f 22 } //1 CallByName DestinationKat, "Co"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}