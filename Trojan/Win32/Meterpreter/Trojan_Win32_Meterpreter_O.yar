
rule Trojan_Win32_Meterpreter_O{
	meta:
		description = "Trojan:Win32/Meterpreter.O,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 68 58 a4 53 e5 ff d5 } //01 00 
		$a_01_1 = {68 64 6e 73 61 54 68 4c 77 26 07 ff d5 } //01 00 
		$a_01_2 = {50 68 6a c9 9c c9 ff d5 } //01 00 
		$a_01_3 = {68 f4 00 8e cc ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_O_2{
	meta:
		description = "Trojan:Win32/Meterpreter.O,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 24 c6 96 87 52 89 44 90 01 02 e8 90 02 0a c7 04 24 4c 77 26 07 90 00 } //01 00 
		$a_03_1 = {77 73 32 5f c7 44 24 90 01 01 33 32 2e 64 90 02 06 c6 44 24 90 01 01 00 e8 90 00 } //01 00 
		$a_01_2 = {ff d0 83 ec 04 c7 04 24 99 a5 74 61 e8 } //01 00 
		$a_03_3 = {c7 04 24 52 f3 e2 51 e8 90 01 04 c7 04 24 5f 78 54 ee 90 00 } //00 00 
		$a_00_4 = {78 80 00 } //00 05 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_O_3{
	meta:
		description = "Trojan:Win32/Meterpreter.O,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {65 48 8b 52 60 90 02 04 48 8b 52 18 90 02 04 48 8b 52 20 90 00 } //01 00 
		$a_01_1 = {6a 40 41 59 68 00 10 00 00 41 58 48 89 f2 48 31 c9 41 ba 58 a4 53 e5 ff d5 } //01 00 
		$a_01_2 = {6a 00 48 89 f9 41 ba ad 9e 5f bb ff d5 } //01 00 
		$a_01_3 = {6a 00 59 49 c7 c2 f0 b5 a2 56 ff d5 } //01 00 
		$a_01_4 = {5c 5c 2e 5c 70 69 70 65 5c } //01 00  \\.\pipe\
		$a_01_5 = {6a 00 59 bb e0 1d 2a 0a 41 89 da ff d5 } //00 00 
		$a_00_6 = {78 9e 00 } //00 03 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_O_4{
	meta:
		description = "Trojan:Win32/Meterpreter.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 8b 80 88 00 00 00 48 85 c0 74 } //01 00 
		$a_03_1 = {ff e0 58 41 59 5a 48 8b 12 e9 90 01 04 5d 48 ba 01 00 00 00 00 00 00 00 48 8d 8d 90 01 02 00 00 41 ba 31 8b 6f 87 ff d5 bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5 90 00 } //01 00 
		$a_01_2 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5 } //00 00 
		$a_00_3 = {78 a3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Meterpreter_O_5{
	meta:
		description = "Trojan:Win32/Meterpreter.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 } //01 00 
		$a_03_1 = {ff e0 5f 5f 5a 8b 12 eb 90 01 01 5d 6a 01 8d 85 90 01 01 00 00 00 50 68 31 8b 6f 87 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5 90 00 } //01 00 
		$a_01_2 = {bb 47 13 72 6f 6a 00 53 ff d5 } //01 00 
		$a_03_3 = {ff e0 5f 5f 5a 8b 12 eb 8d 5d 8d 85 90 01 01 00 00 00 50 68 4c 77 26 07 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5 90 00 } //00 00 
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}