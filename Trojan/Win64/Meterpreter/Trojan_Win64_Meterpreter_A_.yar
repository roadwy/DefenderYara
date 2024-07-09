
rule Trojan_Win64_Meterpreter_A_{
	meta:
		description = "Trojan:Win64/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 be 77 73 32 5f 33 32 00 00 41 } //1
		$a_01_1 = {41 ba 4c 77 26 07 ff } //1
		$a_01_2 = {4d 31 c9 49 89 f0 48 89 da 48 89 f9 41 ba 02 d9 c8 5f ff d5 48 83 c4 20 48 01 c3 48 29 c6 75 e0 } //2
		$a_01_3 = {41 ba 58 a4 53 e5 ff } //1
		$a_01_4 = {41 02 1c 00 48 89 c2 80 e2 0f 02 1c 16 41 8a 14 00 41 86 14 18 41 88 14 00 fe c0 75 e3 } //1
		$a_01_5 = {fe c0 41 02 1c 00 41 8a 14 00 41 86 14 18 41 88 14 00 41 02 14 18 41 8a 14 10 41 30 11 49 ff c1 } //1
		$a_01_6 = {48 ff c9 75 db 5f 41 ff e7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Trojan_Win64_Meterpreter_A__2{
	meta:
		description = "Trojan:Win64/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_1 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00 } //1
		$a_01_2 = {b8 0a 4c 53 75 } //1
		$a_03_3 = {8e 4e 0e ec 74 [0-05] aa fc 0d 7c 74 [0-05] 54 ca af 91 74 [0-05] 1b c6 46 79 [0-05] f2 32 f6 0e 75 } //1
		$a_03_4 = {8b 5f 28 45 33 c0 33 d2 48 83 c9 ff ?? 03 ?? ff 94 24 88 00 00 00 45 33 c0 ?? 8b ?? 41 8d ?? ?? ff d3 48 8b c3 } //1
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 [0-10] ff d6 } //2
		$a_03_6 = {3c 45 8b cb 33 c9 ?? 03 ?? 41 b8 00 30 00 00 [0-10] ff d6 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*2+(#a_03_6  & 1)*2) >=7
 
}
rule Trojan_Win64_Meterpreter_A__3{
	meta:
		description = "Trojan:Win64/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {49 be 77 73 32 5f 33 32 00 00 41 56 } //1
		$a_01_1 = {44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 } //1
		$a_01_2 = {41 ba c2 db 37 67 ff d5 } //1
		$a_01_3 = {41 ba b7 e9 38 ff ff d5 } //1
		$a_01_4 = {41 ba 74 ec 3b e1 ff d5 } //1
		$a_01_5 = {49 b8 63 6d 64 00 00 00 00 00 41 50 41 50 48 89 e2 57 57 57 4d 31 c0 6a 0d 59 41 50 e2 fc } //2
		$a_01_6 = {66 c7 44 24 54 01 01 48 8d 44 24 18 c6 00 68 48 89 e6 56 50 41 50 41 50 41 50 49 ff c0 41 50 49 ff c8 4d 89 c1 4c 89 c1 41 ba 79 cc 3f 86 ff d5 } //1
		$a_01_7 = {bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5 48 83 c4 28 3c 06 7c 0a 80 fb e0 75 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}