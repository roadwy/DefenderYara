
rule Trojan_Linux_RShell_A_MTB{
	meta:
		description = "Trojan:Linux/RShell.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 72 65 76 73 68 65 6c 6c 2f 63 6c 69 65 6e 74 2f 68 6f 73 74 2e 67 6f } //1 /revshell/client/host.go
		$a_01_1 = {2f 63 6c 69 65 6e 74 2e 28 2a 48 6f 73 74 29 2e 68 61 6e 64 6c 65 43 6f 6d 6d 61 6e 64 } //1 /client.(*Host).handleCommand
		$a_01_2 = {72 65 64 2e 74 65 61 6d 2f 67 6f 2d 72 65 64 2f 64 6e 73 } //1 red.team/go-red/dns
		$a_01_3 = {70 72 6f 78 79 2e 73 65 72 76 65 46 6f 72 77 61 72 64 } //1 proxy.serveForward
		$a_01_4 = {69 63 6d 70 74 75 6e 6e 65 6c 2e 6e 65 77 43 6c 69 65 6e 74 } //1 icmptunnel.newClient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}