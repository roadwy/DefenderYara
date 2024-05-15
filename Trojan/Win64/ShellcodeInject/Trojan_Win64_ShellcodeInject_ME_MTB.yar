
rule Trojan_Win64_ShellcodeInject_ME_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b 06 c1 e0 02 2b c8 41 8d 47 ff ff c1 42 32 1c 19 41 8b c9 42 88 1c 18 } //01 00 
		$a_01_1 = {73 68 65 6c 6c 2e 62 69 6e } //01 00  shell.bin
		$a_01_2 = {49 6e 6a 65 63 74 20 73 68 65 6c 6c 63 6f 64 65 21 21 21 } //00 00  Inject shellcode!!!
	condition:
		any of ($a_*)
 
}