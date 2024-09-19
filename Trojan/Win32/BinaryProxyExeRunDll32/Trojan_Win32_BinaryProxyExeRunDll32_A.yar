
rule Trojan_Win32_BinaryProxyExeRunDll32_A{
	meta:
		description = "Trojan:Win32/BinaryProxyExeRunDll32.A,SIGNATURE_TYPE_CMDHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //3 rundll32.exe
		$a_00_1 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 } //3 \windows\temp\
		$a_00_2 = {2e 00 64 00 6c 00 6c 00 } //3 .dll
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3) >=9
 
}