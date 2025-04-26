
rule HackTool_Linux_ReverseSSH_A_MTB{
	meta:
		description = "HackTool:Linux/ReverseSSH.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,11 00 11 00 07 00 00 "
		
	strings :
		$a_01_0 = {72 65 76 65 72 73 65 5f 73 73 68 2f 63 6d 64 2f 63 6c 69 65 6e 74 } //5 reverse_ssh/cmd/client
		$a_01_1 = {73 79 73 63 61 6c 6c 2e 62 69 6e 64 } //5 syscall.bind
		$a_01_2 = {55 73 65 72 41 67 65 6e 74 } //5 UserAgent
		$a_01_3 = {46 6f 72 63 65 41 74 74 65 6d 70 74 48 54 54 50 32 } //1 ForceAttemptHTTP2
		$a_01_4 = {68 74 74 70 2e 66 61 6b 65 4c 6f 63 6b 65 72 } //1 http.fakeLocker
		$a_01_5 = {73 75 62 73 79 73 74 65 6d 73 2e 73 65 74 75 69 64 } //1 subsystems.setuid
		$a_01_6 = {6d 61 78 49 6e 63 6f 6d 69 6e 67 50 61 79 6c 6f 61 64 } //1 maxIncomingPayload
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=17
 
}