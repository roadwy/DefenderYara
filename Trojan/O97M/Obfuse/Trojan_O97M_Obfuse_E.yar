
rule Trojan_O97M_Obfuse_E{
	meta:
		description = "Trojan:O97M/Obfuse.E,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 41 73 20 53 74 72 69 6e 67 29 0d 0a 43 6f 6e 73 74 20 } //1
		$a_01_1 = {29 0d 0a 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 0d 0a 20 20 20 49 66 20 } //1
		$a_01_2 = {3d 20 31 20 54 6f 20 4c 65 6e 28 } //1 = 1 To Len(
		$a_03_3 = {20 3d 20 43 68 72 28 41 73 63 28 [0-0f] 29 20 2b 20 33 29 0d 0a 20 20 20 49 66 20 } //1
		$a_03_4 = {20 3d 20 4d 69 64 28 [0-0f] 2c 20 [0-0f] 2c 20 31 29 0d 0a 20 20 20 49 66 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}