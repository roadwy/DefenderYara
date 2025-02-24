
rule HackTool_Linux_ReverseSSH_B_MTB{
	meta:
		description = "HackTool:Linux/ReverseSSH.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 48 41 53 2f 72 65 76 65 72 73 65 5f 73 73 68 2f 63 6d 64 2f 63 6c 69 65 6e 74 2f 6d 61 69 6e 2e 67 6f } //1 NHAS/reverse_ssh/cmd/client/main.go
		$a_01_1 = {73 75 62 73 79 73 74 65 6d 73 2e 73 65 74 67 69 64 } //1 subsystems.setgid
		$a_01_2 = {63 6c 69 65 6e 74 2f 68 61 6e 64 6c 65 72 73 2f 73 75 62 73 79 73 74 65 6d 73 2f 73 66 74 70 2e 67 6f } //1 client/handlers/subsystems/sftp.go
		$a_01_3 = {72 65 76 65 72 73 65 5f 73 73 68 2f 70 6b 67 2f 6c 6f 67 67 65 72 } //1 reverse_ssh/pkg/logger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}