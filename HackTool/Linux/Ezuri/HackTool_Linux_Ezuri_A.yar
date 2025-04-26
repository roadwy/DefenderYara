
rule HackTool_Linux_Ezuri_A{
	meta:
		description = "HackTool:Linux/Ezuri.A,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 72 75 6e 46 72 6f 6d 4d 65 6d 6f 72 79 } //2 main.runFromMemory
		$a_81_1 = {6d 61 69 6e 2e 61 65 73 44 65 63 } //2 main.aesDec
		$a_81_2 = {63 69 70 68 65 72 2e 4e 65 77 43 46 42 44 65 63 72 79 70 74 65 72 } //2 cipher.NewCFBDecrypter
		$a_81_3 = {58 4f 52 4b 65 79 53 74 72 65 61 6d } //2 XORKeyStream
		$a_81_4 = {6d 61 69 6e 2e 6d 61 69 6e } //2 main.main
		$a_81_5 = {73 79 73 63 61 6c 6c 2e 53 79 73 63 61 6c 6c } //2 syscall.Syscall
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2) >=10
 
}