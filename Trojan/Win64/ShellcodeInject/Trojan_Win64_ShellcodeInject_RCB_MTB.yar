
rule Trojan_Win64_ShellcodeInject_RCB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.RCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 6f 2d 73 68 65 6c 6c 63 6f 64 65 2f 73 68 65 6c 6c 63 6f 64 65 } //1 go-shellcode/shellcode
		$a_01_1 = {41 76 61 69 6c 61 62 6c 65 20 61 63 74 69 6f 6e 73 20 61 72 65 3a 20 27 45 6e 63 72 79 70 74 20 70 61 79 6c 6f 61 64 27 2c 20 27 44 65 63 72 79 70 74 20 70 61 79 6c 6f 61 64 27 2c 20 61 6e 64 20 27 44 65 73 63 72 69 70 20 61 6e 64 20 52 75 6e } //1 Available actions are: 'Encrypt payload', 'Decrypt payload', and 'Descrip and Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}