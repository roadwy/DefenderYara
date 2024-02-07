
rule Trojan_Win32_Meterpreter_A_{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 68 58 a4 53 e5 ff d5 } //01 00 
		$a_01_1 = {68 64 6e 73 61 54 68 4c 77 26 07 ff d5 } //01 00 
		$a_01_2 = {50 68 6a c9 9c c9 ff d5 } //01 00 
		$a_01_3 = {68 f4 00 8e cc ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__2{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 } //01 00 
		$a_01_1 = {68 3a 56 79 a7 ff d5 } //01 00 
		$a_01_2 = {68 2d 06 18 7b ff d5 } //01 00 
		$a_01_3 = {68 58 a4 53 e5 ff d5 } //01 00 
		$a_01_4 = {68 12 96 89 e2 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__3{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6c 6c 20 41 68 33 32 2e 64 68 75 73 65 72 } //01 00  hll Ah32.dhuser
		$a_01_1 = {68 6f 78 58 20 68 61 67 65 42 68 4d 65 73 73 } //01 00  hoxX hageBhMess
		$a_01_2 = {8b 45 3c 8b 54 28 78 } //01 00 
		$a_03_3 = {84 c0 74 07 c1 cf 90 01 01 01 c7 eb f4 3b 7c 24 28 75 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__4{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 } //01 00 
		$a_01_1 = {68 33 32 00 00 68 77 73 32 5f } //01 00  ㍨2栀獷弲
		$a_01_2 = {68 58 a4 53 e5 ff d5 } //01 00 
		$a_01_3 = {68 ea 0f df e0 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__5{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 c2 eb 38 5f 48 89 c6 e8 90 01 04 b9 ea 0f df e0 48 89 c5 e8 90 00 } //01 00 
		$a_01_1 = {48 b8 77 73 32 5f 33 32 2e 64 } //01 00 
		$a_01_2 = {b9 99 a5 74 61 e8 } //01 00 
		$a_03_3 = {b9 02 d9 c8 5f 90 02 04 e8 90 00 } //01 00 
		$a_01_4 = {b9 58 a4 53 e5 e8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__6{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec 74 90 01 01 81 90 01 01 aa fc 0d 7c 74 90 01 01 81 90 01 01 54 ca af 91 74 90 01 01 81 90 01 01 f2 32 f6 0e 90 00 } //01 00 
		$a_01_1 = {83 e8 05 c6 43 05 e9 89 43 06 ff 15 } //01 00 
		$a_01_2 = {c6 46 05 e9 2b c6 83 e8 05 89 46 06 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__7{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } //01 00 
		$a_01_1 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6 } //01 00 
		$a_01_2 = {66 b9 57 05 ff d6 50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__8{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } //01 00 
		$a_01_1 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6 } //01 00 
		$a_01_2 = {66 b9 33 ce ff d6 89 e1 50 b4 0c 50 51 57 51 66 b9 c0 38 ff e6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__9{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ad ad 4e 03 06 3d 32 33 5f 32 75 ef } //01 00 
		$a_01_1 = {8b 6b 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 8b 5c 29 3c 03 dd 03 6c 29 24 57 } //01 00 
		$a_03_2 = {8b f4 56 68 90 01 04 57 ff d5 ad 85 c0 74 ee 90 00 } //02 00 
		$a_03_3 = {ff d3 ad 3d 90 01 04 75 dd ff e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__10{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff } //01 00 
		$a_03_1 = {5c 5c 2e 5c 70 69 70 65 90 02 20 68 da f6 da 4f ff d5 90 00 } //01 00 
		$a_01_2 = {68 58 a4 53 e5 ff d5 } //01 00 
		$a_01_3 = {68 ad 9e 5f bb ff d5 } //01 00 
		$a_01_4 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__11{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 90 02 08 ff 90 00 } //01 00 
		$a_01_1 = {b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } //01 00 
		$a_01_2 = {50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 } //01 00 
		$a_01_3 = {6a 10 56 57 68 99 a5 74 61 ff d5 } //01 00 
		$a_01_4 = {bb f0 b5 a2 56 6a 00 53 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__12{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff e0 5f 5f 5a 8b 12 eb 90 01 01 5d 6a 01 8d 85 9a 00 00 00 50 68 31 8b 6f 87 ff d5 68 47 13 72 6f ff d5 90 00 } //01 00 
		$a_01_1 = {60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 48 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__13{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 24 c6 96 87 52 89 44 90 01 02 e8 90 02 0a c7 04 24 4c 77 26 07 90 00 } //01 00 
		$a_03_1 = {77 73 32 5f c7 44 24 90 01 01 33 32 2e 64 90 02 06 c6 44 24 90 01 01 00 e8 90 00 } //01 00 
		$a_01_2 = {ff d0 83 ec 04 c7 04 24 99 a5 74 61 e8 } //01 00 
		$a_03_3 = {c7 04 24 52 f3 e2 51 e8 90 01 04 c7 04 24 5f 78 54 ee 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__14{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } //01 00 
		$a_01_1 = {53 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6 } //01 00 
		$a_01_2 = {66 53 89 e1 6a 10 51 57 66 b9 80 3b ff d6 } //01 00 
		$a_01_3 = {66 b9 75 49 ff d6 54 54 54 57 66 b9 32 4c ff d6 } //01 00 
		$a_01_4 = {b4 0c 50 51 57 51 66 b9 c0 38 ff e6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__15{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 } //01 00 
		$a_01_1 = {e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 } //01 00 
		$a_01_2 = {50 68 31 8b 6f 87 ff d5 } //01 00 
		$a_01_3 = {bb e0 1d 2a 0a 68 a6 95 bd 9d ff d5 } //01 00 
		$a_01_4 = {bb 47 13 72 6f 6a 00 53 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__16{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 ba 02 d9 c8 5f ff d5 } //01 00 
		$a_01_1 = {41 ba 75 6e 4d 61 ff d5 } //01 00 
		$a_01_2 = {41 ba 58 a4 53 e5 ff d5 } //01 00 
		$a_01_3 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 } //01 00 
		$a_01_4 = {5d 49 be 77 73 32 5f 33 32 00 00 41 56 } //01 00 
		$a_03_5 = {41 ba ea 0f df e0 ff d5 90 02 20 41 ba 99 a5 74 61 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__17{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 db 64 8b 43 30 8b 40 0c 8b 50 1c 8b 12 8b 72 20 ad ad 4e 03 06 3d 32 33 5f 32 } //02 00 
		$a_01_1 = {8b 6a 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 01 e9 8b 41 58 01 e8 8b 71 3c 01 ee 03 69 0c 53 6a 01 6a 02 ff d0 } //01 00 
		$a_01_2 = {68 02 00 11 5c 89 e1 53 b7 0c } //01 00 
		$a_01_3 = {53 51 57 51 6a 10 51 57 56 ff e5 } //01 00 
		$a_01_4 = {68 74 74 70 3a } //00 00  http:
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__18{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 c7 c2 2d 06 18 7b ff d5 } //01 00 
		$a_01_1 = {49 ba 58 a4 53 e5 00 00 00 00 ff d5 } //01 00 
		$a_01_2 = {49 ba 12 96 89 e2 00 00 00 00 ff d5 } //01 00 
		$a_01_3 = {49 c7 c2 f0 b5 a2 56 ff d5 } //01 00 
		$a_01_4 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 } //01 00 
		$a_03_5 = {49 be 77 69 6e 69 6e 65 74 00 90 02 08 49 c7 c2 4c 77 26 07 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__19{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 c7 c2 6c 29 24 7e ff d5 } //01 00 
		$a_01_1 = {49 c7 c2 05 88 9d 70 ff d5 } //01 00 
		$a_01_2 = {49 ba 95 58 bb 91 00 00 00 00 ff d5 } //01 00 
		$a_01_3 = {49 ba d3 58 9d ce 00 00 00 00 ff d5 } //01 00 
		$a_01_4 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 } //01 00 
		$a_03_5 = {49 be 77 69 6e 68 74 74 70 00 90 02 08 49 c7 c2 4c 77 26 07 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__20{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } //01 00 
		$a_01_1 = {95 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6 } //01 00 
		$a_01_2 = {66 b9 a8 6f ff d6 97 68 0a 0a 01 15 } //01 00 
		$a_01_3 = {66 b9 a8 6f ff d6 97 68 c0 a8 01 07 } //01 00 
		$a_01_4 = {66 53 89 e3 6a 10 53 57 66 b9 57 05 ff d6 } //01 00 
		$a_01_5 = {50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__21{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {65 48 8b 52 60 90 02 04 48 8b 52 18 90 02 04 48 8b 52 20 90 00 } //01 00 
		$a_01_1 = {6a 40 41 59 68 00 10 00 00 41 58 48 89 f2 48 31 c9 41 ba 58 a4 53 e5 ff d5 } //01 00 
		$a_01_2 = {6a 00 48 89 f9 41 ba ad 9e 5f bb ff d5 } //01 00 
		$a_01_3 = {6a 00 59 49 c7 c2 f0 b5 a2 56 ff d5 } //01 00 
		$a_01_4 = {5c 5c 2e 5c 70 69 70 65 5c } //01 00  \\.\pipe\
		$a_01_5 = {6a 00 59 bb e0 1d 2a 0a 41 89 da ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__22{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 01 8d 85 b2 00 00 00 50 68 31 8b 6f 87 ff } //01 00 
		$a_02_1 = {6e 65 74 20 75 73 65 72 20 90 1d 20 00 20 90 02 20 20 2f 61 64 64 20 26 26 20 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 90 1d 20 00 20 2f 61 64 64 90 00 } //01 00 
		$a_01_2 = {66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__23{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed } //01 00 
		$a_01_1 = {e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 } //01 00 
		$a_01_2 = {41 ba 31 8b 6f 87 ff d5 } //01 00 
		$a_01_3 = {bb e0 1d 2a 0a 41 ba a6 95 bd 9d ff d5 } //01 00 
		$a_01_4 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__24{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {86 c6 c2 04 18 33 32 2e 64 87 57 36 57 32 } //02 00 
		$a_01_1 = {bb a8 a2 4d bc 87 1c 24 52 } //02 00 
		$a_01_2 = {68 6f 78 58 20 68 61 67 65 42 68 4d 65 73 73 } //01 00  hoxX hageBhMess
		$a_01_3 = {68 8e 4e 0e ec 52 e8 } //01 00 
		$a_01_4 = {88 4c 24 10 89 e1 31 d2 52 53 51 52 ff d0 31 c0 50 ff 55 08 } //01 00 
		$a_01_5 = {8b 6c 24 24 8b 45 3c 8b 54 28 78 01 ea 8b 4a 18 8b 5a 20 01 eb e3 34 49 8b 34 8b 01 ee 31 ff 31 c0 fc ac } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__25{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 } //01 00 
		$a_03_1 = {5c 5c 2e 5c 70 69 70 65 90 02 20 68 45 70 df d4 ff d5 90 00 } //01 00 
		$a_01_2 = {68 58 a4 53 e5 ff d5 } //01 00 
		$a_01_3 = {68 ad 9e 5f bb ff d5 } //01 00 
		$a_01_4 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5 } //01 00 
		$a_01_5 = {ff e1 e8 00 00 00 00 bb f0 b5 a2 56 6a 00 53 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__26{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 } //01 00 
		$a_01_1 = {b8 04 02 00 00 29 c4 48 48 54 50 68 29 80 6b 00 ff d5 } //01 00 
		$a_01_2 = {50 50 50 6a 06 40 50 6a 17 68 ea 0f df e0 } //01 00 
		$a_01_3 = {ff d5 89 c7 6a 1c e8 1c 00 00 00 } //01 00 
		$a_01_4 = {57 68 99 a5 74 61 ff d5 } //01 00 
		$a_01_5 = {6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5 } //01 00 
		$a_01_6 = {68 00 10 00 00 56 6a 00 68 58 a4 53 e5 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__27{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //01 00  刀晥敬瑣癩䱥慯敤r
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_2 = {8e 4e 0e ec 74 90 01 04 aa fc 0d 7c 74 90 01 04 54 ca af 91 74 90 01 04 ef ce e0 60 90 00 } //01 00 
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_4 = {b8 0a 4c 53 75 } //01 00 
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 90 01 01 03 90 01 01 44 8d 49 40 90 02 10 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__28{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,09 00 09 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 3a 56 79 a7 ff d5 } //02 00 
		$a_01_1 = {50 68 57 89 9f c6 ff d5 } //01 00 
		$a_01_2 = {68 2d 06 18 7b ff d5 85 c0 } //02 00 
		$a_01_3 = {68 12 96 89 e2 ff d5 85 c0 } //01 00 
		$a_01_4 = {50 6a 02 6a 02 57 68 da f6 da 4f ff d5 } //04 00 
		$a_01_5 = {6a 00 57 68 31 8b 6f 87 ff d5 } //01 00 
		$a_01_6 = {6a 00 68 f0 b5 a2 56 ff d5 } //01 00 
		$a_01_7 = {58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__29{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 } //01 00 
		$a_01_1 = {68 a6 95 bd 9d ff d3 3c 06 7c 1a 31 c9 64 8b 41 18 39 88 a8 01 00 00 75 0c 8d 93 cf 00 00 00 89 90 a8 01 00 00 31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9 } //01 00 
		$a_01_2 = {53 74 61 67 65 6c 65 73 73 49 6e 69 74 } //01 00  StagelessInit
		$a_01_3 = {47 45 54 20 2f 31 32 33 34 35 36 37 38 39 } //00 00  GET /123456789
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__30{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5e 6a 30 59 64 8b 19 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08 } //01 00 
		$a_01_1 = {57 53 32 5f 33 32 00 5b 8d 4b 20 51 ff d7 } //01 00 
		$a_01_2 = {77 73 32 5f 33 32 00 5b 8d 4b 20 51 ff d7 } //01 00 
		$a_01_3 = {49 8b 34 8b 01 ee 31 ff fc 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2 } //01 00 
		$a_01_4 = {a4 1a 70 c7 a4 ad 2e e9 } //02 00 
		$a_01_5 = {ff 55 24 53 57 ff 55 28 53 54 57 ff 55 20 89 c7 68 43 4d 44 00 } //01 00 
		$a_01_6 = {ff 75 00 68 72 fe b3 16 ff 55 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__31{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 00 68 77 69 6e 68 54 68 4c 77 26 07 ff d5 } //01 00 
		$a_01_1 = {68 04 1f 9d bb ff d5 } //01 00 
		$a_01_2 = {50 68 46 9b 1e c2 ff d5 } //01 00 
		$a_01_3 = {68 00 01 00 00 53 53 53 57 53 50 68 98 10 b3 5b ff d5 } //01 00 
		$a_01_4 = {53 53 53 53 53 53 56 68 95 58 bb 91 ff d5 } //01 00 
		$a_01_5 = {53 56 68 05 88 9d 70 ff d5 } //01 00 
		$a_01_6 = {6a 40 68 00 10 00 00 68 00 00 40 00 53 68 58 a4 53 e5 ff d5 } //01 00 
		$a_01_7 = {57 68 00 20 00 00 53 56 68 6c 29 24 7e ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__32{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 } //01 00 
		$a_01_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } //01 00 
		$a_01_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 } //01 00 
		$a_03_3 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 90 01 01 ff 4e 08 75 90 00 } //01 00 
		$a_03_4 = {68 58 a4 53 e5 ff d5 90 02 0a 6a 00 56 53 57 68 02 d9 c8 5f ff d5 90 00 } //01 00 
		$a_01_5 = {89 e6 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__33{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } //01 00 
		$a_01_1 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb } //01 00 
		$a_03_2 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 90 01 01 8b 07 01 c3 85 c0 75 90 00 } //01 00 
		$a_03_3 = {68 2d 06 18 7b ff d5 85 c0 75 90 02 08 eb 90 01 01 eb 90 01 01 e8 90 00 } //01 00 
		$a_03_4 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 e8 90 01 02 00 00 68 74 74 70 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__34{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 8b 80 88 00 00 00 48 85 c0 74 } //01 00 
		$a_03_1 = {ff e0 58 41 59 5a 48 8b 12 e9 90 01 04 5d 48 ba 01 00 00 00 00 00 00 00 48 8d 8d 90 01 02 00 00 41 ba 31 8b 6f 87 ff d5 bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5 90 00 } //01 00 
		$a_01_2 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__35{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 54 24 04 8d 5a 04 53 ff 12 c2 04 00 } //01 00 
		$a_01_1 = {8b 54 24 04 8b 5a 04 8d 4a 08 51 53 ff 12 c2 04 00 } //01 00 
		$a_01_2 = {8b 54 24 04 ff 72 04 ff 12 c2 04 00 } //01 00 
		$a_01_3 = {73 74 64 61 70 69 5f 6e 65 74 5f 74 63 70 5f 63 6c 69 65 6e 74 } //01 00  stdapi_net_tcp_client
		$a_01_4 = {73 74 64 61 70 69 5f 6e 65 74 5f 74 63 70 5f 73 65 72 76 65 72 } //01 00  stdapi_net_tcp_server
		$a_01_5 = {73 74 64 61 70 69 5f 6e 65 74 5f 75 64 70 5f 63 6c 69 65 6e 74 } //01 00  stdapi_net_udp_client
		$a_01_6 = {73 74 64 61 70 69 5f 66 73 5f 66 69 6c 65 } //00 00  stdapi_fs_file
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__36{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 } //01 00 
		$a_03_1 = {ff e0 5f 5f 5a 8b 12 eb 90 01 01 5d 6a 01 8d 85 90 01 01 00 00 00 50 68 31 8b 6f 87 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5 90 00 } //01 00 
		$a_01_2 = {bb 47 13 72 6f 6a 00 53 ff d5 } //01 00 
		$a_03_3 = {ff e0 5f 5f 5a 8b 12 eb 8d 5d 8d 85 90 01 01 00 00 00 50 68 4c 77 26 07 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__37{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 e3 81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_1 = {81 f9 5d 68 fa 3c 75 90 01 01 8b 90 00 } //01 00 
		$a_03_2 = {b8 0a 4c 53 75 21 8b 45 90 01 01 0f b7 90 00 } //01 00 
		$a_03_3 = {8e 4e 0e ec 74 90 02 03 aa fc 0d 7c 74 90 02 03 54 ca af 91 74 90 02 03 1b c6 46 79 74 90 02 03 f2 32 f6 0e 75 90 00 } //01 00 
		$a_01_4 = {64 a1 30 00 00 00 6a 04 89 75 f8 c7 45 d4 02 00 00 00 8b 40 0c c7 45 c8 01 00 00 00 8b 58 14 89 5d ec 58 85 db } //01 00 
		$a_01_5 = {8b 77 28 33 ff 57 57 6a ff 03 f3 ff 55 d8 33 c0 57 40 50 53 ff d6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__38{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 } //01 00  _ReflectiveLoader@
		$a_01_1 = {75 e3 81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_2 = {8e 4e 0e ec 74 90 02 03 aa fc 0d 7c 74 90 02 03 54 ca af 91 74 90 02 03 f2 32 f6 0e 75 90 00 } //01 00 
		$a_03_3 = {81 f9 5d 68 fa 3c 75 90 01 01 8b 90 00 } //01 00 
		$a_03_4 = {b8 0a 4c 53 75 21 8b 45 90 01 01 0f b7 90 00 } //01 00 
		$a_01_5 = {8b 5e 3c 6a 40 03 de 68 00 30 00 00 89 5d f0 ff 73 50 6a 00 ff } //01 00 
		$a_01_6 = {8b 5d f0 8b 73 28 33 db 53 53 6a ff 03 f7 ff 55 dc 33 c0 53 40 50 57 ff d6 5f 8b c6 5e 5b 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__39{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 db 53 53 53 53 53 68 3a 56 79 a7 ff d5 } //01 00 
		$a_01_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } //01 00 
		$a_01_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb } //01 00 
		$a_03_3 = {68 2d 06 18 7b ff d5 85 c0 75 90 01 01 68 88 13 00 00 68 44 f0 35 e0 ff d5 4f 75 90 00 } //01 00 
		$a_03_4 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 90 01 01 8b 07 01 c3 85 c0 75 90 00 } //01 00 
		$a_03_5 = {68 2d 06 18 7b ff d5 85 c0 75 90 02 20 68 58 a4 53 e5 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__40{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //01 00  刀晥敬瑣癩䱥慯敤r
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_2 = {8e 4e 0e ec 74 90 02 04 aa fc 0d 7c 74 90 02 04 54 ca af 91 74 90 02 04 f2 32 f6 0e 75 90 00 } //01 00 
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_4 = {b8 0a 4c 53 75 } //01 00 
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 90 01 01 03 90 01 01 44 8d 49 40 90 02 04 ff d6 90 00 } //01 00 
		$a_01_6 = {41 8b 5f 28 45 33 c0 33 d2 48 83 c9 ff 49 03 de ff 54 24 68 45 33 c0 49 8b ce 41 8d 50 01 ff d3 48 8b c3 48 83 c4 40 41 5f 41 5e 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__41{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //01 00  刀晥敬瑣癩䱥慯敤r
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_2 = {8e 4e 0e ec 74 90 02 04 aa fc 0d 7c 74 90 02 04 54 ca af 91 74 90 02 04 f2 32 f6 0e 75 90 00 } //01 00 
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_4 = {b8 0a 4c 53 75 } //01 00 
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 90 01 01 03 90 01 01 44 8d 49 40 90 02 04 ff d6 90 00 } //01 00 
		$a_01_6 = {8b 5e 28 45 33 c0 33 d2 48 83 c9 ff 48 03 df ff 54 24 70 45 33 c0 48 8b cf 41 8d 50 01 ff d3 48 8b c3 48 83 c4 28 41 5f 41 5e 41 5d 41 5c 5f 5e 5d 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__42{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 5a e8 00 00 00 00 5b 52 45 55 89 e5 81 c3 90 01 04 ff d3 81 c3 90 01 04 89 3b 53 6a 04 50 ff d0 90 00 } //01 00 
		$a_01_1 = {8b 75 fc 8b 5e 3c 6a 40 03 de 68 00 30 00 00 89 5d f0 ff 73 50 6a 00 ff 55 ec ff 73 50 8b f8 57 89 7d f4 ff 55 e8 8b 53 54 8b ce 85 d2 74 12 8b c7 2b c6 89 45 d8 8b f0 8a 01 88 04 0e 41 4a 75 f7 } //01 00 
		$a_01_2 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__43{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec 74 90 01 01 81 90 01 01 aa fc 0d 7c 74 90 01 01 81 90 01 01 54 ca af 91 74 90 01 01 81 90 01 01 f2 32 f6 0e 90 00 } //01 00 
		$a_01_1 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 } //01 00 
		$a_01_2 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 } //01 00 
		$a_01_3 = {f0 b5 a2 56 } //01 00 
		$a_01_4 = {77 65 62 63 61 6d 5f 61 75 64 69 6f 5f 72 65 63 6f 72 64 } //01 00  webcam_audio_record
		$a_01_5 = {25 54 45 4d 50 25 5c 68 6f 6f 6b 2e 64 6c 6c } //00 00  %TEMP%\hook.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__44{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 8b 76 30 8b 76 0c 8b 76 1c 56 90 01 04 5f 8b 6f 08 ff 37 8b 5d 3c 8b 5c 1d 78 01 eb 8b 4b 18 67 e3 eb 90 00 } //01 00 
		$a_01_1 = {32 17 66 c1 ca 01 ae 75 f7 49 66 39 f2 74 08 67 e3 cb } //01 00 
		$a_01_2 = {66 81 fa da f0 74 1b 66 81 fa 69 27 74 20 6a 32 68 6f 6c 65 33 54 ff d7 } //01 00 
		$a_01_3 = {68 6e 04 22 d4 68 a1 ec ef 99 68 b9 72 92 49 68 74 df 44 6c } //01 00 
		$a_01_4 = {68 4f 79 73 96 68 9e e3 01 c0 } //01 00 
		$a_01_5 = {68 91 33 d2 11 68 77 93 74 96 } //01 00 
		$a_01_6 = {89 e3 56 54 50 6a 17 56 53 ff d7 } //02 00 
		$a_01_7 = {68 6f 67 20 55 68 6f 70 20 74 68 21 64 6e 68 } //01 00  hog Uhop th!dnh
		$a_01_8 = {ac 66 50 3c 55 75 f9 89 e1 31 c0 50 50 51 53 8b 13 8b 4a 50 ff d1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__45{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 90 01 01 aa fc 0d 7c 74 90 01 01 81 90 01 01 54 ca af 91 74 90 01 01 81 90 01 01 f2 32 f6 0e 90 00 } //01 00 
		$a_01_2 = {f0 b5 a2 56 } //01 00 
		$a_01_3 = {fe 0e 32 ea 75 } //01 00 
		$a_01_4 = {6d 69 6d 69 6b 61 74 7a 5f 63 75 73 74 6f 6d 5f 63 6f 6d 6d 61 6e 64 } //01 00  mimikatz_custom_command
		$a_01_5 = {5c 00 5c 00 2e 00 5c 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //01 00  \\.\mimikatz
		$a_01_6 = {4b 00 69 00 77 00 69 00 41 00 6e 00 64 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //00 00  KiwiAndRegistryTools
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__46{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } //01 00 
		$a_01_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } //01 00 
		$a_01_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb } //01 00 
		$a_03_3 = {68 58 a4 53 e5 ff d5 90 02 10 6a 00 56 53 57 68 02 d9 c8 5f ff d5 90 00 } //01 00 
		$a_03_4 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 90 01 01 ff 4e 08 75 90 00 } //01 00 
		$a_01_5 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 89 e8 ff d0 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 } //01 00 
		$a_03_6 = {68 b7 e9 38 ff ff d5 90 02 08 68 74 ec 3b e1 ff d5 90 02 08 68 75 6e 4d 61 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__47{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_1 = {8e 4e 0e ec 74 90 01 01 81 90 01 01 aa fc 0d 7c 74 90 01 01 81 90 01 01 54 ca af 91 74 90 01 01 81 90 01 01 f2 32 f6 0e 90 00 } //01 00 
		$a_01_2 = {f0 b5 a2 56 } //01 00 
		$a_01_3 = {fe 0e 32 ea 75 } //01 00 
		$a_01_4 = {6d 65 74 73 72 76 2e 64 6c 6c 00 00 52 74 6c 43 72 65 61 74 65 55 73 65 72 54 68 72 65 61 64 } //01 00 
		$a_01_5 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 00 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 25 73 20 3e 20 25 73 00 25 73 25 73 2e 64 6c 6c } //01 00 
		$a_01_6 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 61 20 2f 70 3a 25 73 00 2f 74 3a 30 78 25 30 38 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__48{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 41 59 4c 4f 41 44 5f 55 55 49 44 20 3d } //01 00  PAYLOAD_UUID =
		$a_01_1 = {73 75 70 65 72 28 4d 65 74 65 72 70 72 65 74 65 72 46 69 6c 65 2c 20 73 65 6c 66 29 2e 5f 5f 69 6e 69 74 5f 5f 28 29 } //01 00  super(MeterpreterFile, self).__init__()
		$a_01_2 = {73 75 70 65 72 28 4d 65 74 65 72 70 72 65 74 65 72 50 72 6f 63 65 73 73 2c 20 73 65 6c 66 29 2e 5f 5f 69 6e 69 74 5f 5f 28 29 } //01 00  super(MeterpreterProcess, self).__init__()
		$a_01_3 = {65 78 70 6f 72 74 28 4d 65 74 65 72 70 72 65 74 65 72 53 6f 63 6b 65 74 54 43 50 53 65 72 76 65 72 29 } //01 00  export(MeterpreterSocketTCPServer)
		$a_01_4 = {63 6c 61 73 73 20 50 79 74 68 6f 6e 4d 65 74 65 72 70 72 65 74 65 72 28 6f 62 6a 65 63 74 29 3a } //01 00  class PythonMeterpreter(object):
		$a_01_5 = {6d 65 74 20 3d 20 50 79 74 68 6f 6e 4d 65 74 65 72 70 72 65 74 65 72 28 74 72 61 6e 73 70 6f 72 74 29 } //01 00  met = PythonMeterpreter(transport)
		$a_01_6 = {6d 65 74 2e 72 75 6e 28 29 } //00 00  met.run()
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__49{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 17 59 89 cf 31 d2 52 52 6a 03 52 6a 03 68 00 00 00 c0 56 8b 5d 14 ff d3 } //01 00 
		$a_01_1 = {52 8d 5c 24 04 53 52 52 52 52 68 20 00 09 00 50 8b 5d 08 ff d3 } //02 00 
		$a_01_2 = {68 00 10 00 00 6a 01 8d 86 1a 00 00 00 50 8d 86 10 00 00 00 50 6a 0c 8d 46 08 50 8b 5d 00 ff d3 } //01 00 
		$a_01_3 = {68 c8 00 00 00 8b 5d 04 ff d3 89 f9 83 46 08 01 e2 8d 6a 00 8b 5d 10 ff d3 } //01 00 
		$a_00_4 = {66 6d 69 66 73 2e 64 6c 6c 00 } //01 00 
		$a_01_5 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 50 08 8b 78 20 8b 00 3a 4f 18 75 f3 } //03 00 
		$a_01_6 = {68 64 5b 02 ab 68 10 a1 67 05 68 a7 d4 34 3b } //01 00 
		$a_01_7 = {68 96 90 62 d7 68 87 8f 46 ec 68 06 e5 b0 cf 68 dc dd 1a 33 } //01 00 
		$a_03_8 = {83 f9 01 75 0c 51 eb 1c 8b 44 24 1c ff d0 89 c2 59 51 8b 4c bd 00 e8 90 01 04 59 50 47 e2 e0 89 e5 eb 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__50{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 70 69 70 65 5c 73 70 6f 6f 6c 73 73 } //01 00  \pipe\spoolss
		$a_03_1 = {73 61 6d 73 72 76 2e 64 6c 6c 90 02 20 53 61 6d 49 43 6f 6e 6e 65 63 74 90 02 20 53 61 6d 72 4f 70 65 6e 44 6f 6d 61 69 6e 90 00 } //01 00 
		$a_03_2 = {47 6c 6f 62 61 6c 5c 53 41 4d 90 02 20 47 6c 6f 62 61 6c 5c 46 52 45 45 90 00 } //01 00 
		$a_03_3 = {50 6a 00 68 ff 00 0f 00 ff 15 90 01 04 50 ff 15 90 01 04 85 c0 90 01 02 8d 45 dc 50 6a 02 ff 75 f4 ff 15 90 01 04 85 c0 90 00 } //01 00 
		$a_03_4 = {6a 40 68 00 10 00 00 ff 75 f0 6a 00 53 ff 15 90 01 04 89 45 dc 85 c0 90 01 02 8d 4d 90 01 01 51 ff 75 f0 68 6a 2f 00 10 50 53 ff 15 90 01 04 85 c0 90 00 } //01 00 
		$a_03_5 = {6c 73 61 73 73 2e 65 78 65 90 02 20 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 90 00 } //01 00 
		$a_01_6 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 25 73 20 3e 20 25 73 } //00 00  cmd.exe /c echo %s > %s
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__51{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 70 69 70 65 5c 73 70 6f 6f 6c 73 73 } //01 00  \pipe\spoolss
		$a_03_1 = {73 61 6d 73 72 76 2e 64 6c 6c 90 02 20 53 61 6d 49 43 6f 6e 6e 65 63 74 90 02 20 53 61 6d 72 4f 70 65 6e 44 6f 6d 61 69 6e 90 00 } //01 00 
		$a_03_2 = {47 6c 6f 62 61 6c 5c 53 41 4d 90 02 20 47 6c 6f 62 61 6c 5c 46 52 45 45 90 00 } //01 00 
		$a_03_3 = {45 33 c0 48 8b c8 ba ff 00 0f 00 ff 15 90 01 04 85 c0 90 01 02 48 8b 4c 24 48 4c 8d 90 01 03 ba 02 00 00 00 ff 15 90 01 04 85 c0 90 00 } //01 00 
		$a_03_4 = {45 8b fe c7 44 24 20 04 00 00 00 41 b9 00 30 00 00 45 8b c6 33 d2 48 8b cf ff 15 90 01 04 4c 8b f0 48 85 c0 90 01 02 48 89 5c 24 20 45 8b cf 4c 8b c6 48 8b d0 48 8b cf ff 15 90 00 } //01 00 
		$a_03_5 = {6c 73 61 73 73 2e 65 78 65 90 02 20 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 90 00 } //01 00 
		$a_01_6 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 25 73 20 3e 20 25 73 } //00 00  cmd.exe /c echo %s > %s
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__52{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 5a 41 52 55 48 89 e5 48 83 ec 20 48 83 e4 f0 e8 00 00 00 00 5b 48 81 c3 90 01 04 ff d3 48 81 c3 90 01 04 48 89 3b 49 89 d8 6a 04 5a ff d0 90 00 } //01 00 
		$a_01_1 = {48 8b 9c 24 88 00 00 00 48 63 73 3c 33 c9 41 b8 00 30 00 00 48 03 f3 44 8d 49 40 8b 56 50 41 ff d6 8b 56 50 48 8b c8 48 8b f8 41 ff d7 8b 56 54 48 8b cb 41 bb 01 00 00 00 48 85 d2 74 14 4c 8b c7 4c 2b c3 8a 01 41 88 04 08 49 03 cb 49 2b d3 75 f2 44 0f b7 4e 06 0f b7 46 14 4d 85 c9 74 38 48 8d 4e 2c 48 03 c8 8b 51 f8 44 8b 01 44 8b 51 fc 48 03 d7 4c 03 c3 4d 2b cb 4d 85 d2 74 10 41 8a 00 4d 03 c3 88 02 49 03 d3 4d 2b d3 75 f0 } //01 00 
		$a_01_2 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__53{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 22 2f 4f 69 43 41 41 41 41 59 49 6e 6c 4d 63 42 6b 69 31 41 77 69 31 49 4d 69 31 49 55 69 33 49 6f 44 37 64 4b 4a 6a 48 2f } //01 00  [System.Convert]::FromBase64String("/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/
		$a_03_1 = {3a 3a 47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 28 28 90 02 08 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 29 2c 20 28 90 02 08 20 40 28 5b 49 6e 74 50 74 72 5d 2c 90 00 } //01 00 
		$a_03_2 = {3a 3a 47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 28 28 90 02 08 20 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 20 43 72 65 61 74 65 54 68 72 65 61 64 29 2c 20 28 90 02 08 20 40 28 5b 49 6e 74 50 74 72 5d 2c 90 00 } //01 00 
		$a_03_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 29 2c 20 28 90 02 08 20 40 28 5b 49 6e 74 50 74 72 5d 2c 20 5b 49 6e 74 33 32 5d 29 29 29 2e 49 6e 76 6f 6b 65 28 24 90 02 08 2c 30 78 66 66 66 66 66 66 66 66 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_A__54{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 89 e5 56 57 8b 75 08 8b 4d 0c e8 00 00 00 00 58 83 c0 2b 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 0f 00 00 00 66 8c d8 66 8e d0 83 c4 14 5f 5e 5d c2 08 00 8b 3c e4 ff 2a 48 31 c0 57 ff d6 5f 50 c7 44 24 04 23 00 00 00 89 3c 24 ff 2c 24 } //01 00 
		$a_00_1 = {fc 48 89 ce 48 89 e7 48 83 e4 f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 75 72 8b 80 88 00 00 00 } //01 00 
		$a_00_2 = {48 85 c0 74 67 48 01 d0 50 8b 48 18 44 8b 40 20 49 01 d0 e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 58 44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 4f ff ff ff 5d 4d 31 c9 41 51 48 8d 46 18 50 ff 76 10 ff 76 08 41 51 41 51 49 b8 01 00 00 00 00 00 00 00 48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c 48 b8 00 00 00 00 00 00 00 00 eb 0a 48 b8 01 00 00 00 00 00 00 00 48 83 c4 50 48 89 fc c3 } //01 00 
		$a_01_3 = {fc 80 79 10 00 0f 85 13 01 00 00 c6 41 10 01 48 83 ec 78 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 75 72 8b 80 88 00 00 00 48 85 c0 74 67 48 01 d0 50 8b 48 18 44 8b 40 20 49 01 d0 e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 } //01 00 
		$a_01_4 = {e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 58 44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 4f ff ff ff 5d 48 31 d2 65 48 8b 42 30 48 39 90 c8 02 00 00 75 0e 48 8d 95 07 01 00 00 48 89 90 c8 02 00 00 4c 8b 01 4c 8b 49 08 48 31 c9 48 31 d2 51 51 41 ba 38 68 0d 16 ff d5 48 81 c4 a8 00 00 00 c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } //01 00 
		$a_01_5 = {78 46 43 8b 74 24 04 55 89 e5 e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4a 01 d0 50 8b 48 18 8b 58 20 01 d3 e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 eb 86 5b 80 7e 10 00 75 3b c6 46 10 01 68 a6 95 bd 9d ff d3 3c 06 7c 1a 31 c9 64 8b 41 18 39 88 a8 01 00 00 75 0c 8d 93 cf 00 00 00 89 90 a8 01 00 00 31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9 c2 0c 00 00 00 00 00 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}