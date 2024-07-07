
rule Trojan_Win32_Vreikstadi_A{
	meta:
		description = "Trojan:Win32/Vreikstadi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 00 05 80 35 35 c7 40 04 34 3b 0d 7b c7 40 08 04 31 17 68 } //1
		$a_01_1 = {c7 40 1c 05 31 09 68 c7 40 20 17 35 34 3b c7 40 24 66 7b 61 31 } //1
		$a_01_2 = {c7 40 74 c7 78 61 31 c7 40 78 ec 51 11 2b c7 40 7c 5e 07 8e e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}