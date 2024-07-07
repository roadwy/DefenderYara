
rule Backdoor_Linux_Mirai_J_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {75 64 70 72 61 6e 64 } //1 udprand
		$a_00_1 = {62 79 70 61 73 73 } //1 bypass
		$a_00_2 = {74 63 70 2d 72 61 6e 64 } //1 tcp-rand
		$a_00_3 = {61 74 74 61 63 6b 73 2e 63 } //1 attacks.c
		$a_00_4 = {5b 39 36 6d 6b 69 6c 6c 65 72 } //1 [96mkiller
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}