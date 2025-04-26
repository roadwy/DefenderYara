
rule Trojan_Win32_Kuang_E{
	meta:
		description = "Trojan:Win32/Kuang.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 65 69 72 64 31 37 33 40 79 61 68 6f 6f 2e 63 6f 6d 00 20 62 79 20 57 65 69 72 64 00 } //1
		$a_01_1 = {45 58 45 00 00 4f 70 65 6e 20 6b 75 61 6e 67 32 20 70 53 65 6e 64 65 72 } //1
		$a_01_2 = {43 6f 64 65 64 20 62 79 20 57 65 69 72 64 } //1 Coded by Weird
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}