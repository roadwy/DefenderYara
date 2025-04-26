
rule Trojan_Win32_Meterpreter_gen_H{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } //1
		$a_01_1 = {53 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6 } //1
		$a_01_2 = {66 53 89 e1 6a 10 51 57 66 b9 80 3b ff d6 } //1
		$a_01_3 = {66 b9 75 49 ff d6 54 54 54 57 66 b9 32 4c ff d6 } //1
		$a_01_4 = {b4 0c 50 51 57 51 66 b9 c0 38 ff e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}