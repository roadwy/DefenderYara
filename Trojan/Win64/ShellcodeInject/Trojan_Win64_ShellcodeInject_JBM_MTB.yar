
rule Trojan_Win64_ShellcodeInject_JBM_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.JBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 95 30 1c 00 00 44 0f b6 04 11 44 88 04 01 48 ff c1 48 3b cf 72 e8 } //2
		$a_81_1 = {4d 6f 76 65 64 20 73 68 65 6c 6c 63 6f 64 65 20 69 6e 74 6f 20 61 6c 6c 6f 63 61 74 65 64 20 6d 65 6d 6f 72 79 } //1 Moved shellcode into allocated memory
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}