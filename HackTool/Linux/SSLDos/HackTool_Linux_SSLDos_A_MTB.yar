
rule HackTool_Linux_SSLDos_A_MTB{
	meta:
		description = "HackTool:Linux/SSLDos.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 53 4c 5f 72 65 6e 65 67 6f 74 69 61 74 65 } //1 SSL_renegotiate
		$a_01_1 = {74 68 63 2d 73 73 6c 2d 64 6f 73 2e 63 } //1 thc-ssl-dos.c
		$a_01_2 = {73 73 6c 5f 68 61 6e 64 73 68 61 6b 65 5f 69 6f } //1 ssl_handshake_io
		$a_01_3 = {25 64 20 74 63 70 5f 63 6f 6e 6e 65 63 74 5f 69 6f } //1 %d tcp_connect_io
		$a_01_4 = {2e 2f 74 68 63 2d 73 73 6c 2d 64 6f 73 20 5b 6f 70 74 69 6f 6e 73 5d 20 3c 69 70 3e 20 3c 70 6f 72 74 3e } //1 ./thc-ssl-dos [options] <ip> <port>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}