
rule Trojan_Linux_CloakNDag_A_MTB{
	meta:
		description = "Trojan:Linux/CloakNDag.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 6e 73 70 6f 72 74 } //1 transport
		$a_01_1 = {55 73 65 72 41 67 65 6e 74 } //1 UserAgent
		$a_01_2 = {73 65 73 73 69 6f 6e 49 64 } //1 sessionId
		$a_01_3 = {67 6f 6c 61 6e 67 2e 6f 72 67 2f 78 2f 63 72 79 70 74 6f 2f 63 68 61 63 68 61 32 30 70 6f 6c 79 31 33 30 35 } //1 golang.org/x/crypto/chacha20poly1305
		$a_01_4 = {6f 73 2f 65 78 65 63 2e 43 6f 6d 6d 61 6e 64 } //1 os/exec.Command
		$a_01_5 = {6f 73 2e 73 74 61 72 74 50 72 6f 63 65 73 73 } //1 os.startProcess
		$a_01_6 = {68 74 74 70 2e 73 6f 63 6b 73 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 } //1 http.socksUsernamePassword
		$a_01_7 = {6d 61 69 6e 2e 72 65 61 64 44 69 72 } //1 main.readDir
		$a_01_8 = {6d 61 69 6e 2e 72 75 6e 43 6f 6d 6d 61 6e 64 } //1 main.runCommand
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}