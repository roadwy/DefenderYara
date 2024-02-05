
rule Trojan_Win64_Meterpreter_C{
	meta:
		description = "Trojan:Win64/Meterpreter.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
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