
rule Trojan_Win32_Meterpreter_gen_C{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 } //1
		$a_01_1 = {68 33 32 00 00 68 77 73 32 5f } //1 ㍨2栀獷弲
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Meterpreter_gen_C_2{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {b9 c2 eb 38 5f 48 89 c6 e8 ?? ?? ?? ?? b9 ea 0f df e0 48 89 c5 e8 } //1
		$a_01_1 = {48 b8 77 73 32 5f 33 32 2e 64 } //1
		$a_01_2 = {b9 99 a5 74 61 e8 } //1
		$a_03_3 = {b9 02 d9 c8 5f [0-04] e8 } //1
		$a_01_4 = {b9 58 a4 53 e5 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Meterpreter_gen_C_3{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {5f 5a 8b 12 eb ?? 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 } //2
		$a_01_1 = {68 3a 56 79 a7 ff d5 } //1
		$a_01_2 = {68 2d 06 18 7b ff d5 } //1
		$a_01_3 = {68 58 a4 53 e5 ff d5 } //1
		$a_01_4 = {68 12 96 89 e2 ff d5 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Trojan_Win32_Meterpreter_gen_C_4{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff } //1
		$a_03_1 = {5c 5c 2e 5c 70 69 70 65 [0-20] 68 da f6 da 4f ff d5 } //1
		$a_01_2 = {68 58 a4 53 e5 ff d5 } //1
		$a_01_3 = {68 ad 9e 5f bb ff d5 } //1
		$a_01_4 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Meterpreter_gen_C_5{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 2d 06 18 7b ff d5 85 c0 75 } //1
		$a_03_1 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75 } //1
		$a_01_2 = {68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 } //1
		$a_01_3 = {68 3a 56 79 a7 ff d5 } //1
		$a_01_4 = {68 58 a4 53 e5 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Meterpreter_gen_C_6{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 } //1
		$a_03_1 = {5c 5c 2e 5c 70 69 70 65 [0-20] 68 45 70 df d4 ff d5 } //1
		$a_01_2 = {68 58 a4 53 e5 ff d5 } //1
		$a_01_3 = {68 ad 9e 5f bb ff d5 } //1
		$a_01_4 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5 } //1
		$a_01_5 = {ff e1 e8 00 00 00 00 bb f0 b5 a2 56 6a 00 53 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule Trojan_Win32_Meterpreter_gen_C_7{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } //1
		$a_01_1 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb } //1
		$a_03_2 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75 } //1
		$a_03_3 = {68 2d 06 18 7b ff d5 85 c0 75 [0-08] eb ?? eb ?? e8 } //1
		$a_03_4 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 e8 ?? ?? 00 00 68 74 74 70 3a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Meterpreter_gen_C_8{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 db 53 53 53 53 53 68 3a 56 79 a7 ff d5 } //1
		$a_01_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } //1
		$a_01_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb } //1
		$a_03_3 = {68 2d 06 18 7b ff d5 85 c0 75 ?? 68 88 13 00 00 68 44 f0 35 e0 ff d5 4f 75 } //1
		$a_03_4 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75 } //1
		$a_03_5 = {68 2d 06 18 7b ff d5 85 c0 75 [0-20] 68 58 a4 53 e5 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}
rule Trojan_Win32_Meterpreter_gen_C_9{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } //1
		$a_01_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } //1
		$a_01_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb } //1
		$a_03_3 = {68 58 a4 53 e5 ff d5 [0-10] 6a 00 56 53 57 68 02 d9 c8 5f ff d5 } //1
		$a_03_4 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 ?? ff 4e 08 75 } //1
		$a_01_5 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 89 e8 ff d0 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } //1
		$a_03_6 = {68 b7 e9 38 ff ff d5 [0-08] 68 74 ec 3b e1 ff d5 [0-08] 68 75 6e 4d 61 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=5
 
}
rule Trojan_Win32_Meterpreter_gen_C_10{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 2f 4f 69 43 41 41 41 41 59 49 6e 6c 4d 63 42 6b 69 31 41 77 69 31 49 4d 69 31 49 55 69 33 49 6f 44 37 64 4b 4a 6a 48 2f } //1 [System.Convert]::FromBase64String("/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/
		$a_03_1 = {3a 3a 47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 28 28 [0-08] 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 29 2c 20 28 [0-08] 20 40 28 5b 49 6e 74 50 74 72 5d 2c } //1
		$a_03_2 = {3a 3a 47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 28 28 [0-08] 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 43 72 65 61 74 65 54 68 72 65 61 64 29 2c 20 28 [0-08] 20 40 28 5b 49 6e 74 50 74 72 5d 2c } //1
		$a_03_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 29 2c 20 28 [0-08] 20 40 28 5b 49 6e 74 50 74 72 5d 2c 20 5b 49 6e 74 33 32 5d 29 29 29 2e 49 6e 76 6f 6b 65 28 24 [0-08] 2c 30 78 66 66 66 66 66 66 66 66 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}