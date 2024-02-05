
rule Trojan_Win64_Meterpreter_gen_A{
	meta:
		description = "Trojan:Win64/Meterpreter.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 be 77 73 32 5f 33 32 00 00 41 56 } //01 00 
		$a_01_1 = {44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 } //01 00 
		$a_01_2 = {41 ba c2 db 37 67 ff d5 } //01 00 
		$a_01_3 = {41 ba b7 e9 38 ff ff d5 } //01 00 
		$a_01_4 = {41 ba 74 ec 3b e1 ff d5 } //02 00 
		$a_01_5 = {49 b8 63 6d 64 00 00 00 00 00 41 50 41 50 48 89 e2 57 57 57 4d 31 c0 6a 0d 59 41 50 e2 fc } //01 00 
		$a_01_6 = {66 c7 44 24 54 01 01 48 8d 44 24 18 c6 00 68 48 89 e6 56 50 41 50 41 50 41 50 49 ff c0 41 50 49 ff c8 4d 89 c1 4c 89 c1 41 ba 79 cc 3f 86 ff d5 } //01 00 
		$a_01_7 = {bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5 48 83 c4 28 3c 06 7c 0a 80 fb e0 75 05 } //00 00 
	condition:
		any of ($a_*)
 
}