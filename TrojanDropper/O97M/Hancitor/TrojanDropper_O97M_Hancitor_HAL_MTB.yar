
rule TrojanDropper_O97M_Hancitor_HAL_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {26 20 6a 73 64 20 26 } //1 & jsd &
		$a_03_2 = {44 69 6d 20 66 75 20 41 73 20 53 74 72 69 6e 67 90 0c 02 00 66 75 20 3d 20 67 6c 6f 67 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 90 0c 02 00 4e 61 6d 65 20 6d 79 68 6f 6d 65 20 26 20 22 5c [0-08] 2e 74 6d 70 22 20 41 73 20 66 75 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_03_3 = {43 61 6c 6c 20 73 73 73 73 90 0c 02 00 44 69 6d 20 70 75 73 68 73 74 72 20 41 73 20 53 74 72 69 6e 67 } //1
		$a_03_4 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 90 0c 02 00 43 61 6c 6c 20 67 6f 74 6f 74 77 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}