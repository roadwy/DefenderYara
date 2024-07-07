
rule TrojanDropper_O97M_Hancitor_HAU_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 } //1 Sub gotodown()
		$a_01_2 = {43 61 6c 6c 20 68 68 68 73 73 } //1 Call hhhss
		$a_01_3 = {26 20 22 6d 22 20 26 20 22 70 22 20 41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 } //1 & "m" & "p" As ActiveDocument.Application.StartupPath & "\" & "W0rd.dll"
		$a_03_4 = {72 65 70 69 64 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
		$a_01_5 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 73 66 20 26 } //1 strFileExists = Dir(sf &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}