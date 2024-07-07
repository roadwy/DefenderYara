
rule Trojan_O97M_Thunbin_A{
	meta:
		description = "Trojan:O97M/Thunbin.A,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 CreateObject("Shell.Application
		$a_01_1 = {2e 4f 70 65 6e } //1 .Open
		$a_01_2 = {2e 53 74 61 74 75 73 20 3d 20 32 30 30 20 54 68 65 6e } //1 .Status = 200 Then
		$a_01_3 = {2e 53 61 76 65 54 6f 46 69 6c 65 } //1 .SaveToFile
		$a_01_4 = {3d 20 31 30 20 2d 20 39 } //1 = 10 - 9
		$a_01_5 = {69 75 75 71 74 3b 30 30 75 69 66 2f 66 62 73 75 69 2f 6d 6a 30 7f 74 68 75 62 75 69 62 6e 30 71 76 75 75 7a 30 31 2f 38 33 30 78 34 33 30 71 76 75 75 7a 2f 66 79 66 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}