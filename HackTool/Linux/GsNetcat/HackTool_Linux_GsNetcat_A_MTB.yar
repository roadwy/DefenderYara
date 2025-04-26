
rule HackTool_Linux_GsNetcat_A_MTB{
	meta:
		description = "HackTool:Linux/GsNetcat.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 67 73 2d 6e 65 74 63 61 74 2e 63 } //1 _gs-netcat.c
		$a_01_1 = {47 53 4f 43 4b 45 54 5f 53 4f 43 4b 53 5f 49 50 } //1 GSOCKET_SOCKS_IP
		$a_01_2 = {6a 61 69 6c 73 68 65 6c 6c } //1 jailshell
		$a_01_3 = {66 69 6c 65 74 72 61 6e 73 66 65 72 2e 63 } //1 filetransfer.c
		$a_01_4 = {47 53 5f 64 61 65 6d 6f 6e 69 7a 65 } //1 GS_daemonize
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}