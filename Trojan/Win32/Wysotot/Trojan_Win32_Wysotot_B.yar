
rule Trojan_Win32_Wysotot_B{
	meta:
		description = "Trojan:Win32/Wysotot.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {57 6a 17 6a 00 ff d6 6a 01 6a 00 53 8d 85 90 01 04 68 90 01 04 50 e8 90 00 } //1
		$a_01_1 = {30 0c 30 02 c8 40 3b c7 72 f6 b0 01 c3 } //1
		$a_01_2 = {74 09 3c 5a 74 05 34 5a 88 04 11 41 3b ce 72 eb } //1
		$a_01_3 = {44 50 72 6f 74 65 63 74 53 76 63 2e 70 64 62 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}