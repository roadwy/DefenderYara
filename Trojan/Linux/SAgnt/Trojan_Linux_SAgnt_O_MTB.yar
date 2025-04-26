
rule Trojan_Linux_SAgnt_O_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.O!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 78 73 68 65 6c 6c 2f 73 72 63 2f 68 74 74 70 73 63 6c 69 65 6e 74 2f 63 6c 69 65 6e 74 2e 67 6f } //1 vxshell/src/httpsclient/client.go
		$a_01_1 = {74 61 73 6b 2e 73 74 61 72 74 53 6f 63 6b 73 } //1 task.startSocks
		$a_01_2 = {74 61 73 6b 2e 65 78 65 63 75 74 65 43 6d 64 } //1 task.executeCmd
		$a_01_3 = {2f 66 6f 72 77 61 72 64 2e 4e 65 77 53 68 65 6c 6c 43 6c 69 65 6e 74 } //1 /forward.NewShellClient
		$a_01_4 = {2f 73 63 61 6e 2e 70 6f 72 74 43 6f 6e 6e 65 63 74 } //1 /scan.portConnect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}