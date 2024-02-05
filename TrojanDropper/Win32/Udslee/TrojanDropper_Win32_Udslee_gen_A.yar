
rule TrojanDropper_Win32_Udslee_gen_A{
	meta:
		description = "TrojanDropper:Win32/Udslee.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 03 00 "
		
	strings :
		$a_01_0 = {c7 45 e4 cd fc f8 26 68 61 1d 00 00 e8 } //03 00 
		$a_01_1 = {c7 45 e4 d1 08 2e 55 68 ef 1b 00 00 e8 } //03 00 
		$a_01_2 = {c7 45 e4 cd fc a1 8b 68 6e 1b 00 00 e8 } //03 00 
		$a_01_3 = {c7 45 e4 d1 08 2e 59 68 9b 20 00 00 e8 } //01 00 
		$a_01_4 = {70 64 5b 64 76 5d 00 } //01 00 
		$a_01_5 = {73 64 72 76 49 6e 73 74 61 6c 6c 00 } //01 00 
		$a_01_6 = {76 62 69 66 75 65 6b 7a 6e 6d 40 67 6a 69 74 6b 00 } //01 00 
		$a_01_7 = {69 65 72 75 68 64 73 6c 6c 65 6f 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}