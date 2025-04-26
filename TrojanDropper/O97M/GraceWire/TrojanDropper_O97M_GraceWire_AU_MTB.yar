
rule TrojanDropper_O97M_GraceWire_AU_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 2c 20 22 [0-08] 2e 78 6c 73 78 22 29 2c 20 22 22 29 } //1
		$a_03_1 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-10] 2c 20 22 2e 7a 69 70 22 29 2c 20 22 22 29 } //1
		$a_01_2 = {46 69 6c 65 57 68 65 72 65 50 75 74 54 6f 32 2e 43 6f 70 79 48 65 72 65 20 46 69 6c 65 57 68 65 72 65 50 75 74 54 6f 2e 49 74 65 6d 73 2e 49 74 65 6d 28 55 73 65 72 46 6f 72 6d 36 2e 4c 61 62 65 6c 32 2e 54 61 67 29 } //1 FileWherePutTo2.CopyHere FileWherePutTo.Items.Item(UserForm6.Label2.Tag)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}