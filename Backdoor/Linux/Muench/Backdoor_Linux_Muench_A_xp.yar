
rule Backdoor_Linux_Muench_A_xp{
	meta:
		description = "Backdoor:Linux/Muench.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 75 65 6e 63 68 } //1 Muench
		$a_01_1 = {62 61 63 6b 64 6f 6f 72 2e 63 } //1 backdoor.c
		$a_01_2 = {63 6f 6d 6d 61 6e 64 73 20 66 6f 6c 6c 6f 77 65 64 } //1 commands followed
		$a_01_3 = {2f 62 69 6e 2f 73 68 } //1 /bin/sh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}