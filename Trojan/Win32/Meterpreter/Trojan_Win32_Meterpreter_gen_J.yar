
rule Trojan_Win32_Meterpreter_gen_J{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 } //01 00 
		$a_01_1 = {b8 04 02 00 00 29 c4 48 48 54 50 68 29 80 6b 00 ff d5 } //01 00 
		$a_01_2 = {50 50 50 6a 06 40 50 6a 17 68 ea 0f df e0 } //01 00 
		$a_01_3 = {ff d5 89 c7 6a 1c e8 1c 00 00 00 } //01 00 
		$a_01_4 = {57 68 99 a5 74 61 ff d5 } //01 00 
		$a_01_5 = {6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5 } //01 00 
		$a_01_6 = {68 00 10 00 00 56 6a 00 68 58 a4 53 e5 ff d5 } //00 00 
		$a_00_7 = {5d 04 00 } //00 0d 
	condition:
		any of ($a_*)
 
}