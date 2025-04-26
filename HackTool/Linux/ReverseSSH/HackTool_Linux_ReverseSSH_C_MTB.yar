
rule HackTool_Linux_ReverseSSH_C_MTB{
	meta:
		description = "HackTool:Linux/ReverseSSH.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 52 75 6e } //1 main.Run
		$a_01_1 = {6d 61 69 6e 2e 46 6f 72 6b } //1 main.Fork
		$a_01_2 = {72 65 76 65 72 73 65 5f 73 73 68 } //1 reverse_ssh
		$a_01_3 = {63 6c 69 65 6e 74 2f 68 61 6e 64 6c 65 72 73 2e 4c 6f 63 61 6c 46 6f 72 77 61 72 64 } //1 client/handlers.LocalForward
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}