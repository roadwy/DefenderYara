
rule Backdoor_Win32_Remcos_QW_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {50 6f 6c 54 72 61 67 65 74 2e 76 62 70 } //PolTraget.vbp  3
		$a_80_1 = {64 65 6e 63 69 65 } //dencie  3
		$a_80_2 = {73 74 75 64 65 6e 74 73 5f 61 6e 64 5f 65 6d 70 6c 6f 79 65 65 73 2e 54 6f 67 67 6c 65 53 74 61 74 65 } //students_and_employees.ToggleState  3
		$a_80_3 = {44 54 50 69 63 6b 65 72 } //DTPicker  3
		$a_80_4 = {4b 65 79 41 73 63 69 69 } //KeyAscii  3
		$a_80_5 = {4b 65 79 43 6f 64 65 } //KeyCode  3
		$a_80_6 = {53 79 73 41 6c 6c 6f 63 53 74 72 69 6e 67 42 79 74 65 4c 65 6e } //SysAllocStringByteLen  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}