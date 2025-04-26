
rule Trojan_Linux_Deimos_A_MTB{
	meta:
		description = "Trojan:Linux/Deimos.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 44 65 69 6d 6f 73 43 32 2f 44 65 69 6d 6f 73 43 32 2f 61 67 65 6e 74 73 2f 72 65 73 6f 75 72 63 65 73 2f 73 68 65 6c 6c 69 6e 6a 65 63 74 2e 53 68 65 6c 6c 49 6e 6a 65 63 74 } //1 /DeimosC2/DeimosC2/agents/resources/shellinject.ShellInject
		$a_01_1 = {73 68 65 6c 6c 63 6f 64 65 5f 6c 69 6e 75 78 2e 67 6f } //1 shellcode_linux.go
		$a_01_2 = {2f 6c 69 62 2f 70 72 69 76 69 6c 65 67 65 73 2f 69 73 61 64 6d 69 6e 5f 6c 69 6e 75 78 2e 67 6f } //1 /lib/privileges/isadmin_linux.go
		$a_01_3 = {2f 72 65 73 6f 75 72 63 65 73 2f 61 67 65 6e 74 66 75 6e 63 74 69 6f 6e 73 2e 53 68 6f 75 6c 64 49 44 69 65 } //1 /resources/agentfunctions.ShouldIDie
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}