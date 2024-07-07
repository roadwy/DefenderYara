
rule Trojan_Win32_Crastic_gen_B{
	meta:
		description = "Trojan:Win32/Crastic.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f8 02 74 18 39 b5 } //1
		$a_01_1 = {80 3c 01 5c 75 06 42 83 fa 01 77 79 40 3b c6 72 e2 83 fa 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}