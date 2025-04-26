
rule HackTool_Linux_Sshscan_C_MTB{
	meta:
		description = "HackTool:Linux/Sshscan.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 52 75 6e 5f 53 73 68 } //1 main.Run_Ssh
		$a_01_1 = {6d 61 69 6e 2e 44 69 61 6c 53 73 68 } //1 main.DialSsh
		$a_01_2 = {6d 61 69 6e 2e 54 68 72 65 61 64 5f 4f 6e 65 } //1 main.Thread_One
		$a_01_3 = {6d 61 69 6e 2e 43 68 65 63 6b 41 72 63 68 } //1 main.CheckArch
		$a_01_4 = {6d 61 69 6e 2e 43 68 65 63 6b 53 73 68 } //1 main.CheckSsh
		$a_01_5 = {6d 61 69 6e 2e 74 69 6d 65 6b 65 65 70 } //1 main.timekeep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}