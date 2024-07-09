
rule Trojan_Win32_Minxer_gen_A{
	meta:
		description = "Trojan:Win32/Minxer.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6d 73 75 70 64 61 74 65 2e 37 7a 00 [0-09] 70 72 6f 78 79 2e 63 6f 6e 66 } //1
		$a_01_1 = {00 6d 73 75 70 64 61 74 65 37 31 5c 00 } //1
		$a_01_2 = {2e 64 6c 6c 00 61 73 64 61 73 64 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}