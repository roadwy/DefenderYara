
rule Trojan_Win32_Sabsik_ABK_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 63 72 61 63 6b 73 6d } //1 .cracksm
		$a_01_1 = {30 49 4a 44 42 65 77 46 47 7a 58 43 39 6b 45 79 56 47 5a 5a 57 6a 37 68 36 4a 49 48 59 57 65 51 6a } //10 0IJDBewFGzXC9kEyVGZZWj7h6JIHYWeQj
		$a_01_2 = {52 65 67 4f 70 65 6e 4b 65 79 45 78 57 } //1 RegOpenKeyExW
		$a_01_3 = {52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 41 } //1 RegQueryValueExA
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_5 = {2e 5c 6d 61 69 6c 73 6c 6f 74 5c 73 79 73 74 65 6d 5f 61 6c 6c 6f 63 5f 6d 65 6d 33 } //10 .\mailslot\system_alloc_mem3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10) >=24
 
}