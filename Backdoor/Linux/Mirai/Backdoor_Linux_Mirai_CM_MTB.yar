
rule Backdoor_Linux_Mirai_CM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 90 02 20 2f 73 68 90 00 } //3
		$a_00_1 = {2d 4f 20 2d 3e 20 77 77 77 77 3b 20 73 68 20 77 77 77 77 } //3 -O -> wwww; sh wwww
		$a_00_2 = {76 64 73 6f 5f 63 6c 6f 63 6b 5f 67 65 74 74 69 6d 65 } //1 vdso_clock_gettime
		$a_00_3 = {68 6e 6f 70 71 62 } //1 hnopqb
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=7
 
}