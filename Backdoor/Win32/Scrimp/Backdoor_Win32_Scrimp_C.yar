
rule Backdoor_Win32_Scrimp_C{
	meta:
		description = "Backdoor:Win32/Scrimp.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 6e 6b 65 79 2e 64 61 74 00 61 66 78 6d 73 69 6e 63 69 65 6e 00 } //5
		$a_01_1 = {20 3e 20 00 4d 69 63 6f 53 6f 66 74 45 } //5
		$a_01_2 = {77 73 63 73 63 6f 6e 2e 64 6c 6c 00 31 32 } //1
		$a_01_3 = {6d 6f 6e 6b 65 79 2e 64 6c 6c 00 26 31 32 } //1 潭歮祥搮汬☀㈱
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}