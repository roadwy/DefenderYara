
rule Backdoor_Linux_DinodasRAT_A_MTB{
	meta:
		description = "Backdoor:Linux/DinodasRAT.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 6e 69 66 69 6c 65 2e 63 70 70 } //1 inifile.cpp
		$a_00_1 = {63 68 6b 63 6f 6e 66 69 67 20 2d 2d 6c 69 73 74 20 7c 20 67 72 65 70 20 25 73 } //1 chkconfig --list | grep %s
		$a_00_2 = {6d 79 73 68 65 6c 6c 2e 63 70 70 } //1 myshell.cpp
		$a_00_3 = {63 68 6b 63 6f 6e 66 69 67 20 2d 2d 64 65 6c 20 25 73 } //1 chkconfig --del %s
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}