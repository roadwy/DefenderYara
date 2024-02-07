
rule Trojan_Win32_Meterpreter_gen_R{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 01 00 "
		
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