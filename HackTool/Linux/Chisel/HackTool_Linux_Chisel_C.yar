
rule HackTool_Linux_Chisel_C{
	meta:
		description = "HackTool:Linux/Chisel.C,SIGNATURE_TYPE_ELFHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_80_0 = {63 68 69 73 65 6c 2d 76 } //chisel-v  10
		$a_80_1 = {74 75 6e 6e 65 6c 2e 43 6f 6e 66 69 67 } //tunnel.Config  1
		$a_80_2 = {73 79 73 63 61 6c 6c 2e 53 6f 63 6b 65 74 } //syscall.Socket  1
		$a_80_3 = {73 79 73 63 61 6c 6c 2e 41 63 63 65 70 74 } //syscall.Accept  1
		$a_80_4 = {73 79 73 63 61 6c 6c 2e 72 65 63 76 66 72 6f 6d } //syscall.recvfrom  1
		$a_80_5 = {73 79 73 63 61 6c 6c 2e 73 65 6e 64 66 69 6c 65 } //syscall.sendfile  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=14
 
}