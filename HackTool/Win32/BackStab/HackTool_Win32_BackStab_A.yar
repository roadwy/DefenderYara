
rule HackTool_Win32_BackStab_A{
	meta:
		description = "HackTool:Win32/BackStab.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_80_0 = {5c 42 61 63 6b 73 74 61 62 2e 70 64 62 } //\Backstab.pdb  5
		$a_80_1 = {4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 } //Killing process  5
		$a_80_2 = {5c 64 65 76 69 63 65 5c 70 72 6f 63 65 78 70 } //\device\procexp  1
		$a_80_3 = {70 72 6f 63 65 78 70 2e 70 64 62 } //procexp.pdb  1
		$a_02_4 = {70 00 72 00 6f 00 63 00 65 00 78 00 70 00 [0-0c] 2e 00 73 00 79 00 73 00 } //1
		$a_02_5 = {70 72 6f 63 65 78 70 [0-0c] 2e 73 79 73 } //1
		$a_80_6 = {70 72 6f 63 65 78 70 36 34 } //procexp64  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_80_6  & 1)*1) >=11
 
}