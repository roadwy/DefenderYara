
rule Trojan_Win32_Nebuler_gen_F{
	meta:
		description = "Trojan:Win32/Nebuler.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_00_1 = {4d 53 53 4d 53 47 53 00 25 73 5c 25 73 } //1
		$a_00_2 = {5b 62 72 61 6e 64 5d 00 5b 76 65 72 73 69 6f 6e 5d 00 00 00 5b 75 69 64 5d } //1
		$a_02_3 = {53 68 75 74 64 6f 77 6e 90 02 04 53 74 61 72 74 75 70 90 02 04 54 65 73 74 90 09 19 2e 64 6c 6c 90 02 04 49 6e 73 74 90 02 04 52 75 6e 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}