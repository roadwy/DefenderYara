
rule HackTool_Linux_SshBrute_A_MTB{
	meta:
		description = "HackTool:Linux/SshBrute.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {42 72 75 74 65 20 73 73 68 20 61 74 74 61 63 6b 20 66 69 6e 69 73 68 65 64 21 } //1 Brute ssh attack finished!
		$a_00_1 = {53 53 48 20 61 74 74 61 63 6b 20 6f 6e 20 70 6f 72 74 } //1 SSH attack on port
		$a_00_2 = {70 61 73 73 2e 6c 73 74 } //1 pass.lst
		$a_00_3 = {43 68 65 63 6b 20 69 70 3a 20 25 73 20 77 69 74 68 20 75 73 65 72 20 25 73 20 61 6e 64 20 70 61 73 73 20 25 73 20 6f 6e 20 70 6f 72 74 3a } //1 Check ip: %s with user %s and pass %s on port:
		$a_00_4 = {69 70 73 2e 6c 73 74 } //1 ips.lst
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}