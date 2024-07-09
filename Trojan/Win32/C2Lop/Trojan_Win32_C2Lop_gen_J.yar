
rule Trojan_Win32_C2Lop_gen_J{
	meta:
		description = "Trojan:Win32/C2Lop.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_07_0 = {6a 00 ff 15 90 09 06 00 ff 15 } //1
		$a_07_1 = {6a 00 ff 15 90 09 06 00 ff 90 17 06 01 01 01 01 01 01 91 92 93 95 96 97 } //1
		$a_07_2 = {6a 00 ff 15 90 09 03 00 ff 90 17 07 01 01 01 01 01 01 01 50 51 52 53 55 56 57 } //1
		$a_07_3 = {6a 00 ff 15 90 09 02 00 ff 90 17 07 01 01 01 01 01 01 01 d0 d1 d2 d3 d5 d6 d7 } //1
	condition:
		((#a_07_0  & 1)*1+(#a_07_1  & 1)*1+(#a_07_2  & 1)*1+(#a_07_3  & 1)*1) >=1
 
}