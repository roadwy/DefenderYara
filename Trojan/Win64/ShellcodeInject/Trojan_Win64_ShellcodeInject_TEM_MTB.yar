
rule Trojan_Win64_ShellcodeInject_TEM_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.TEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 63 6f 64 65 20 61 64 64 72 65 73 73 3a } //1 Shellcode address:
		$a_01_1 = {56 75 6c 6e 65 72 61 62 6c 65 20 64 6c 6c 20 62 61 73 65 20 61 64 64 72 65 73 73 3a } //1 Vulnerable dll base address:
		$a_01_2 = {43 72 65 61 74 65 54 68 72 65 61 64 20 66 61 69 6c 65 64 } //1 CreateThread failed
		$a_01_3 = {57 52 58 20 69 6e 6a 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c } //1 WRX injection successful
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}