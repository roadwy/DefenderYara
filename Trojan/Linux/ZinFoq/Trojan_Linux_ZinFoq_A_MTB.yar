
rule Trojan_Linux_ZinFoq_A_MTB{
	meta:
		description = "Trojan:Linux/ZinFoq.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 72 63 2f 6d 6f 64 65 2f 68 74 74 70 41 6e 64 54 63 70 2f 73 68 65 6c 6c 2f 53 68 65 6c 6c 4c 69 6e 75 78 2e 45 78 65 63 5f 73 68 65 6c 6c } //1 src/mode/httpAndTcp/shell/ShellLinux.Exec_shell
		$a_01_1 = {73 72 63 2f 6d 6f 64 65 2f 70 72 6f 63 65 73 73 2f 50 72 6f 63 65 73 73 4c 69 6e 75 78 2e 73 65 6e 64 42 6f 64 79 } //1 src/mode/process/ProcessLinux.sendBody
		$a_01_2 = {73 72 63 2f 6d 6f 64 65 2f 75 74 69 6c 73 2e 53 65 6e 64 44 61 74 61 42 79 50 6f 73 74 } //1 src/mode/utils.SendDataByPost
		$a_01_3 = {2f 68 74 74 70 41 6e 64 54 63 70 2f 73 68 65 6c 6c 2f 53 68 65 6c 6c 4c 69 6e 75 78 2e 53 68 65 6c 6c } //1 /httpAndTcp/shell/ShellLinux.Shell
		$a_01_4 = {2f 68 74 74 70 41 6e 64 54 63 70 2f 69 6e 46 6f 72 77 61 72 64 2e 61 64 64 54 61 73 6b } //1 /httpAndTcp/inForward.addTask
		$a_01_5 = {2f 68 74 74 70 41 6e 64 54 63 70 2f 73 6f 63 6b 65 74 35 51 75 69 63 6b 2e 28 2a 70 72 6f 78 79 29 2e 67 65 74 41 64 64 72 50 6f 72 74 } //1 /httpAndTcp/socket5Quick.(*proxy).getAddrPort
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}