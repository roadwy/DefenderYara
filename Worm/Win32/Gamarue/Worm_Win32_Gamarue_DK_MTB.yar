
rule Worm_Win32_Gamarue_DK_MTB{
	meta:
		description = "Worm:Win32/Gamarue.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_80_0 = {43 72 65 61 74 65 46 69 6c 65 57 } //CreateFileW  3
		$a_80_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //ShellExecuteW  3
		$a_80_2 = {73 6b 74 6f 70 2e 69 6e 69 } //sktop.ini  3
		$a_80_3 = {30 23 30 30 30 38 30 46 30 4b 30 50 30 55 30 } //0#00080F0K0P0U0  3
		$a_80_4 = {30 2e 31 4a 31 51 31 5a 31 66 31 6e 31 75 31 7c } //0.1J1Q1Z1f1n1u1|  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=15
 
}