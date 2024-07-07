
rule TrojanDropper_O97M_Hancitor_HAS_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 } //1 Sub gotodown()
		$a_01_2 = {53 75 62 20 73 73 73 73 28 29 } //1 Sub ssss()
		$a_01_3 = {26 20 6a 73 64 20 26 20 22 6c 6c 22 20 26 20 68 68 } //1 & jsd & "ll" & hh
		$a_03_4 = {43 61 6c 6c 20 73 73 73 73 90 0c 02 00 44 69 6d 20 70 75 73 68 73 74 72 20 41 73 20 53 74 72 69 6e 67 90 0c 02 00 70 75 73 68 73 74 72 20 3d 20 22 5c 57 90 00 } //1
		$a_01_5 = {26 20 79 79 20 26 20 70 75 73 68 73 74 72 20 26 20 22 6c } //1 & yy & pushstr & "l
		$a_01_6 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //1 Call regsrva.ShellExecute(fa, yy, " ", SW_SHOWNORMAL)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}