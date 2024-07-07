
rule Trojan_O97M_Bynoco_PA{
	meta:
		description = "Trojan:O97M/Bynoco.PA,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 6d 54 61 67 20 3d 20 63 72 79 73 6c 65 72 2e 54 61 67 } //1 formTag = crysler.Tag
		$a_01_1 = {3d 20 74 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 2e 41 63 74 69 6f 6e 73 2e 43 72 65 61 74 65 28 61 74 65 29 } //1 = taskDefinition.Actions.Create(ate)
		$a_01_2 = {43 61 6c 6c 20 77 68 65 72 65 54 6f 2e 52 65 67 69 73 74 65 72 54 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 28 20 5f 0d 0a 20 20 20 20 22 53 68 63 65 64 75 6c 65 64 20 75 70 64 61 74 65 20 74 61 73 6b 22 2c 20 74 61 73 6b 44 65 66 69 6e 69 74 69 6f 6e 2c 20 36 2c 20 2c 20 2c 20 33 29 } //1
		$a_01_3 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}