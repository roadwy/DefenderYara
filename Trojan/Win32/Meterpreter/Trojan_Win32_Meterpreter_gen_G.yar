
rule Trojan_Win32_Meterpreter_gen_G{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 00 68 77 69 6e 68 54 68 4c 77 26 07 ff d5 } //1
		$a_01_1 = {68 04 1f 9d bb ff d5 } //1
		$a_01_2 = {50 68 46 9b 1e c2 ff d5 } //1
		$a_01_3 = {68 00 01 00 00 53 53 53 57 53 50 68 98 10 b3 5b ff d5 } //1
		$a_01_4 = {53 53 53 53 53 53 56 68 95 58 bb 91 ff d5 } //1
		$a_01_5 = {53 56 68 05 88 9d 70 ff d5 } //1
		$a_01_6 = {6a 40 68 00 10 00 00 68 00 00 40 00 53 68 58 a4 53 e5 ff d5 } //1
		$a_01_7 = {57 68 00 20 00 00 53 56 68 6c 29 24 7e ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}