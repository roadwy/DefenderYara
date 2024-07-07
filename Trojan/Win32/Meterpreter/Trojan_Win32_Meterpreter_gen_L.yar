
rule Trojan_Win32_Meterpreter_gen_L{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {5e 6a 30 59 64 8b 19 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08 } //1
		$a_01_1 = {57 53 32 5f 33 32 00 5b 8d 4b 20 51 ff d7 } //1
		$a_01_2 = {77 73 32 5f 33 32 00 5b 8d 4b 20 51 ff d7 } //1
		$a_01_3 = {49 8b 34 8b 01 ee 31 ff fc 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2 } //1
		$a_01_4 = {a4 1a 70 c7 a4 ad 2e e9 } //1
		$a_01_5 = {ff 55 24 53 57 ff 55 28 53 54 57 ff 55 20 89 c7 68 43 4d 44 00 } //2
		$a_01_6 = {ff 75 00 68 72 fe b3 16 ff 55 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=5
 
}