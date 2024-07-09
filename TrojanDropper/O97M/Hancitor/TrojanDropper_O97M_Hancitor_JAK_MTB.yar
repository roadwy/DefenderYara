
rule TrojanDropper_O97M_Hancitor_JAK_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 69 63 2e 64 6c 6c } //1 Static.dll
		$a_01_1 = {53 75 62 20 72 6e 65 65 28 6d 79 68 6f 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 68 73 61 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub rnee(myhome As String, hsa As String)
		$a_03_2 = {4e 61 6d 65 20 6d 79 68 6f 6d 65 20 26 20 22 5c [0-10] 2e 70 75 6d 70 6c 22 20 41 73 20 68 73 61 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_3 = {46 75 6e 63 74 69 6f 6e 20 66 75 78 6b 28 29 } //1 Function fuxk()
		$a_03_4 = {66 75 78 6b 20 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 54 61 62 6c 65 73 28 31 29 2e 43 65 6c 6c 28 31 2c 20 31 29 2e 52 61 6e 67 65 2e 54 65 78 74 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}