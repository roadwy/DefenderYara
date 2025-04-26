
rule Trojan_Win64_ShellcodeInject_GLN_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.GLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 20 49 44 20 74 6f 20 69 6e 6a 65 63 74 20 73 68 65 6c 6c 63 6f 64 65 20 69 6e 74 6f } //1 Process ID to inject shellcode into
		$a_01_1 = {47 65 74 74 69 6e 67 20 61 20 68 61 6e 64 6c 65 20 74 6f 20 50 72 6f 63 65 73 73 20 49 44 } //1 Getting a handle to Process ID
		$a_01_2 = {43 61 6c 6c 69 6e 67 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 20 6f 6e 20 50 49 44 } //1 Calling VirtualAllocEx on PID
		$a_01_3 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 77 72 6f 74 65 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 50 49 44 } //1 Successfully wrote shellcode to PID
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}