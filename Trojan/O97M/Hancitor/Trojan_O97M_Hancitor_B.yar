
rule Trojan_O97M_Hancitor_B{
	meta:
		description = "Trojan:O97M/Hancitor.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //1 For Output As #
		$a_00_1 = {50 72 69 6e 74 20 23 } //1 Print #
		$a_02_2 = {77 73 68 2e 52 75 6e 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 90 0f 01 00 2e 68 74 61 22 2c } //1
		$a_00_3 = {3d 20 66 73 6f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 67 64 66 66 73 20 26 20 22 36 66 73 64 46 66 61 2e 63 6f 6d 22 2c 20 54 72 75 65 29 } //1 = fso.CreateTextFile(gdffs & "6fsdFfa.com", True)
		$a_00_4 = {3d 20 49 73 45 78 65 52 75 6e 6e 69 6e 67 28 22 6e 33 36 30 22 20 26 20 } //1 = IsExeRunning("n360" & 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}