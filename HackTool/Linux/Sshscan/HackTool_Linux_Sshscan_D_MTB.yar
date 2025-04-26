
rule HackTool_Linux_Sshscan_D_MTB{
	meta:
		description = "HackTool:Linux/Sshscan.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 74 72 79 53 53 48 2e 49 6e 73 65 63 75 72 65 49 67 6e 6f 72 65 48 6f 73 74 4b 65 79 2e 66 75 6e 63 34 } //1 main.trySSH.InsecureIgnoreHostKey.func4
		$a_01_1 = {6d 61 69 6e 2e 65 78 74 72 61 63 74 49 50 73 46 72 6f 6d 48 69 73 74 6f 72 79 } //1 main.extractIPsFromHistory
		$a_01_2 = {6d 61 69 6e 2e 74 72 79 53 53 48 2e 50 61 73 73 77 6f 72 64 2e 66 75 6e 63 33 } //1 main.trySSH.Password.func3
		$a_01_3 = {6d 61 69 6e 2e 74 72 79 53 53 48 2e 50 72 69 6e 74 66 2e 66 75 6e 63 35 } //1 main.trySSH.Printf.func5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}