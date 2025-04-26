
rule Trojan_Win32_Delf_NS_MTB{
	meta:
		description = "Trojan:Win32/Delf.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {32 32 32 2e 37 33 2e 38 35 2e 31 31 37 } //2 222.73.85.117
		$a_01_1 = {31 31 36 2e 39 2e 31 34 33 2e 31 31 32 } //2 116.9.143.112
		$a_01_2 = {62 6c 63 67 7a 77 6c 2e 72 61 72 } //1 blcgzwl.rar
		$a_01_3 = {77 65 6e 79 6f 6e 67 30 30 36 } //1 wenyong006
		$a_01_4 = {66 7a 63 6b 63 6b 73 6a } //1 fzckcksj
		$a_01_5 = {50 72 69 76 69 6c 65 67 65 64 20 69 6e 73 74 72 75 63 74 69 6f 6e } //1 Privileged instruction
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}