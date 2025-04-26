
rule Backdoor_Linux_Emperor_A_MTB{
	meta:
		description = "Backdoor:Linux/Emperor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {65 6d 70 33 72 30 72 } //2 emp3r0r
		$a_00_1 = {76 69 63 74 69 6d 53 69 7a 65 } //2 victimSize
		$a_00_2 = {55 73 65 72 41 67 65 6e 74 } //1 UserAgent
		$a_00_3 = {73 79 73 63 61 6c 6c 2e 73 6f 63 6b 65 74 } //1 syscall.socket
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}