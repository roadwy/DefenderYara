
rule Trojan_Win32_SharPyShell_STE{
	meta:
		description = "Trojan:Win32/SharPyShell.STE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_80_0 = {53 68 61 72 50 79 53 68 65 6c 6c } //SharPyShell  1
		$a_80_1 = {72 75 6e 74 69 6d 65 5f 63 6f 6d 70 69 6c 65 72 5f 61 65 73 2e 64 6c 6c } //runtime_compiler_aes.dll  1
		$a_02_2 = {53 00 68 00 61 00 72 00 50 00 79 00 [0-0a] 6d 00 73 00 63 00 6f 00 72 00 6c 00 69 00 62 00 } //1
		$a_02_3 = {53 68 61 72 50 79 [0-0a] 6d 73 63 6f 72 6c 69 62 } //1
		$a_80_4 = {41 45 53 45 6e 63 00 41 45 53 44 65 63 00 52 75 6e } //AESEnc  1
		$a_80_5 = {47 65 74 42 79 74 65 73 00 63 6f 64 65 00 70 61 73 73 77 6f 72 64 00 41 72 72 61 79 } //GetBytes  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=2
 
}