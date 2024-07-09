
rule Trojan_Win32_ShellCodeRunner_GPA_MTB{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d7 8a 86 ?? ?? ?? ?? 2c 03 56 68 } //1
		$a_81_1 = {45 78 65 63 75 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 } //1 Executing shellcode
		$a_81_2 = {53 68 65 6c 6c 63 6f 64 65 20 65 78 65 63 75 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 } //1 Shellcode execution complete
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}