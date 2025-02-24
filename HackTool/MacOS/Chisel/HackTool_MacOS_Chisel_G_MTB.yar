
rule HackTool_MacOS_Chisel_G_MTB{
	meta:
		description = "HackTool:MacOS/Chisel.G!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 74 75 6e 6e 65 6c 5f 69 6e 5f 70 72 6f 78 79 2e 67 6f } //1 /tunnel_in_proxy.go
		$a_01_1 = {6d 61 69 6e 2e 67 65 6e 65 72 61 74 65 50 69 64 46 69 6c 65 } //1 main.generatePidFile
		$a_01_2 = {2f 74 75 6e 6e 65 6c 5f 6f 75 74 5f 73 73 68 2e 67 6f } //1 /tunnel_out_ssh.go
		$a_01_3 = {73 65 72 76 65 72 2f 73 65 72 76 65 72 5f 6c 69 73 74 65 6e 2e 67 6f } //1 server/server_listen.go
		$a_01_4 = {2f 6a 70 69 6c 6c 6f 72 61 2f 72 65 71 75 65 73 74 6c 6f 67 } //1 /jpillora/requestlog
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}