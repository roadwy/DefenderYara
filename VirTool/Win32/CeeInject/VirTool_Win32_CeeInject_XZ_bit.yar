
rule VirTool_Win32_CeeInject_XZ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.XZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {77 73 70 72 69 6e 74 66 28 70 [0-10] 27 25 73 25 73 25 73 25 73 25 73 25 69 25 73 27 [0-10] 27 6e 74 [0-20] 64 6c 6c 3a 3a 4e 74 43 27 [0-10] 27 72 65 61 74 [0-10] 65 53 65 63 74 } //1
		$a_03_1 = {77 73 70 72 69 6e 74 66 28 70 [0-30] 25 73 25 73 25 73 25 73 25 64 [0-20] 61 70 56 69 [0-20] 65 77 4f [0-20] 66 53 65 63 74 } //1
		$a_03_2 = {2a 28 26 74 32 35 35 29 [0-20] 2e 72 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}