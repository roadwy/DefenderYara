
rule Trojan_Win64_Meterpreter_gen_B{
	meta:
		description = "Trojan:Win64/Meterpreter.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 be 77 73 32 5f 33 32 00 00 41 } //01 00 
		$a_01_1 = {41 ba 4c 77 26 07 ff } //02 00 
		$a_01_2 = {4d 31 c9 49 89 f0 48 89 da 48 89 f9 41 ba 02 d9 c8 5f ff d5 48 83 c4 20 48 01 c3 48 29 c6 75 e0 } //01 00 
		$a_01_3 = {41 ba 58 a4 53 e5 ff } //01 00 
		$a_01_4 = {41 02 1c 00 48 89 c2 80 e2 0f 02 1c 16 41 8a 14 00 41 86 14 18 41 88 14 00 fe c0 75 e3 } //01 00 
		$a_01_5 = {fe c0 41 02 1c 00 41 8a 14 00 41 86 14 18 41 88 14 00 41 02 14 18 41 8a 14 10 41 30 11 49 ff c1 } //01 00 
		$a_01_6 = {48 ff c9 75 db 5f 41 ff e7 } //00 00 
		$a_00_7 = {5d 04 00 } //00 1b 
	condition:
		any of ($a_*)
 
}