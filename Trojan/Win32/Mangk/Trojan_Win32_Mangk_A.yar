
rule Trojan_Win32_Mangk_A{
	meta:
		description = "Trojan:Win32/Mangk.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 4f 01 83 c7 01 84 c9 75 f6 8b c8 c1 e9 02 f3 a5 8b c8 6a 38 8d 44 24 10 83 e1 03 6a 00 50 f3 a4 e8 } //1
		$a_01_1 = {49 27 6d 20 4d 72 2e 4b 21 68 74 74 70 3a 2f 2f 77 77 77 2e } //1 I'm Mr.K!http://www.
		$a_02_2 = {2d 20 4d 72 2e 4b 22 [0-05] 6b 6d 69 61 6f 2e 63 6f 6d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}