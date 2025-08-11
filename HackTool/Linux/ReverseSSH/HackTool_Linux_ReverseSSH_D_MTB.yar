
rule HackTool_Linux_ReverseSSH_D_MTB{
	meta:
		description = "HackTool:Linux/ReverseSSH.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 52 65 76 65 72 73 65 50 6f 72 74 46 6f 72 77 61 72 64 69 6e 67 43 61 6c 6c 62 61 63 6b } //1 createReversePortForwardingCallback
		$a_01_1 = {6d 61 69 6e 2e 63 72 65 61 74 65 53 53 48 53 65 73 73 69 6f 6e 48 61 6e 64 6c 65 72 } //1 main.createSSHSessionHandler
		$a_01_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 46 61 68 72 6a 2f 72 65 76 65 72 73 65 2d 73 73 68 } //1 github.com/Fahrj/reverse-ssh
		$a_01_3 = {6d 61 69 6e 2e 63 72 65 61 74 65 50 61 73 73 77 6f 72 64 48 61 6e 64 6c 65 72 } //1 main.createPasswordHandler
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}