
rule Trojan_Linux_Mirai_HAG_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,69 00 69 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 4c 69 6e 75 78 2e 53 68 65 6c 6c } //10 ShellLinux.Shell
		$a_01_1 = {53 68 65 6c 6c 4c 69 6e 75 78 2e 45 78 65 63 5f 73 68 65 6c 6c } //20 ShellLinux.Exec_shell
		$a_01_2 = {50 72 6f 63 65 73 73 4c 69 6e 75 78 2e 73 65 6e 64 42 6f 64 79 } //15 ProcessLinux.sendBody
		$a_01_3 = {50 72 6f 63 65 73 73 4c 69 6e 75 78 2e 50 72 6f 63 65 73 73 54 61 73 6b } //20 ProcessLinux.ProcessTask
		$a_01_4 = {63 6c 69 65 6e 74 20 66 69 6e 69 73 68 65 64 } //15 client finished
		$a_01_5 = {2f 63 72 65 61 63 6b 2f 70 74 79 2e 53 74 61 72 74 } //20 /creack/pty.Start
		$a_01_6 = {68 74 74 70 41 6e 64 54 63 70 } //5 httpAndTcp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*15+(#a_01_3  & 1)*20+(#a_01_4  & 1)*15+(#a_01_5  & 1)*20+(#a_01_6  & 1)*5) >=105
 
}