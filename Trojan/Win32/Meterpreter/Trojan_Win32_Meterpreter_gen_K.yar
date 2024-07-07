
rule Trojan_Win32_Meterpreter_gen_K{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } //1
		$a_01_1 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6 } //1
		$a_01_2 = {66 b9 57 05 ff d6 50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Meterpreter_gen_K_2{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } //1
		$a_01_1 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6 } //1
		$a_01_2 = {66 b9 33 ce ff d6 89 e1 50 b4 0c 50 51 57 51 66 b9 c0 38 ff e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Meterpreter_gen_K_3{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } //1
		$a_01_1 = {95 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6 } //1
		$a_01_2 = {66 b9 a8 6f ff d6 97 68 0a 0a 01 15 } //1
		$a_01_3 = {66 b9 a8 6f ff d6 97 68 c0 a8 01 07 } //1
		$a_01_4 = {66 53 89 e3 6a 10 53 57 66 b9 57 05 ff d6 } //1
		$a_01_5 = {50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}