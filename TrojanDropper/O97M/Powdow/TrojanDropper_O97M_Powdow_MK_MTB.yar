
rule TrojanDropper_O97M_Powdow_MK_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.MK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 6d 64 2f 63 66 69 6e 64 73 74 72 2f 62 22 22 70 6f 77 65 72 73 68 65 6c 6c 22 22 22 22 22 26 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 66 75 6c 6c 6e 61 6d 65 26 22 22 22 3e 25 61 70 70 64 61 74 61 25 5c [0-05] 2e 62 61 74 26 26 63 64 2f 64 25 61 70 70 64 61 74 61 25 26 26 90 1b 00 2e 62 61 74 22 } //1
		$a_03_1 = {73 68 65 6c 6c 28 [0-05] 76 62 68 69 64 65 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}