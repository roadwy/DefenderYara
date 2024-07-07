
rule Trojan_Win64_Meterpreter_B{
	meta:
		description = "Trojan:Win64/Meterpreter.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 ba 02 d9 c8 5f ff d5 } //1
		$a_01_1 = {41 ba 58 a4 53 e5 ff d5 } //1
		$a_01_2 = {5d 49 be 77 73 32 5f 33 32 00 00 41 56 } //1
		$a_03_3 = {41 ba ea 0f df e0 ff d5 90 02 20 41 ba 99 a5 74 61 ff d5 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule Trojan_Win64_Meterpreter_B_2{
	meta:
		description = "Trojan:Win64/Meterpreter.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 ba 02 d9 c8 5f ff d5 } //1
		$a_01_1 = {41 ba 75 6e 4d 61 ff d5 } //1
		$a_01_2 = {41 ba 58 a4 53 e5 ff d5 } //1
		$a_01_3 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 } //1
		$a_01_4 = {5d 49 be 77 73 32 5f 33 32 00 00 41 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}