
rule Backdoor_Win32_Delf_LB{
	meta:
		description = "Backdoor:Win32/Delf.LB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 36 25 78 73 76 63 } //2 36%xsvc
		$a_01_1 = {4c 73 45 54 5c 73 45 52 56 49 43 45 53 5c 25 73 } //2 LsET\sERVICES\%s
		$a_02_2 = {73 63 76 73 74 65 6e ?? 6b 2d } //3
		$a_01_3 = {68 63 76 73 5c 32 33 6d 65 74 73 79 53 } //2 hcvs\23metsyS
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_02_2  & 1)*3+(#a_01_3  & 1)*2) >=4
 
}