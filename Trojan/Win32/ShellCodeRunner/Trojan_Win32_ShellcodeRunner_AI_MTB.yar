
rule Trojan_Win32_ShellcodeRunner_AI_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {f3 a5 66 a5 8b f4 6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 ff 15 ?? ?? ?? 00 3b f4 e8 } //2
		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 20 69 73 20 77 72 69 74 74 65 6e 20 74 6f 20 61 6c 6c 6f 63 61 74 65 64 20 6d 65 6d 6f 72 79 21 } //2 Shellcode is written to allocated memory!
		$a_01_2 = {6d 73 66 68 65 20 62 79 68 6c 63 6f 64 68 53 68 65 6c 31 } //1 msfhe byhlcodhShel1
		$a_01_3 = {68 6c 6c 20 41 68 33 32 2e 64 68 75 73 65 72 30 } //1 hll Ah32.dhuser0
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}