
rule Trojan_Win32_Meterpreter_gen_N{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
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