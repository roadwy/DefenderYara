
rule Trojan_Win32_Meterpreter_gen_F{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 [0-08] ff } //1
		$a_01_1 = {b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } //1
		$a_01_2 = {50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 } //1
		$a_01_3 = {6a 10 56 57 68 99 a5 74 61 ff d5 } //1
		$a_01_4 = {bb f0 b5 a2 56 6a 00 53 ff d5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}