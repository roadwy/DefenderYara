
rule TrojanDropper_O97M_Hancitor_HAX_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {26 20 6a 73 64 20 26 } //1 & jsd &
		$a_01_2 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 } //1 Sub gotodown()
		$a_01_3 = {53 75 62 20 68 68 68 68 68 28 29 } //1 Sub hhhhh()
		$a_01_4 = {44 69 6d 20 70 6f 73 6c 20 41 73 20 53 74 72 69 6e 67 } //1 Dim posl As String
		$a_01_5 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 29 } //1 Call jop(myhome, hsa)
		$a_01_6 = {41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 } //1 As ActiveDocument.Application.StartupPath & "\" & "W0rd.dll"
		$a_03_7 = {26 20 70 75 73 68 73 74 72 20 26 20 22 6c 6c 22 20 26 20 90 02 08 20 26 20 22 73 74 61 6c 6c 46 6f 6e 74 22 90 00 } //1
		$a_01_8 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //1 Call regsrva.ShellExecute(fa, yy, " ", SW_SHOWNORMAL)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}