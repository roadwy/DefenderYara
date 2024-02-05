
rule Trojan_Win32_Meterpreter_gen_O{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 01 00 "
		
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