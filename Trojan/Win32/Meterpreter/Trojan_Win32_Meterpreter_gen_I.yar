
rule Trojan_Win32_Meterpreter_gen_I{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 db 64 8b 43 30 8b 40 0c 8b 50 1c 8b 12 8b 72 20 ad ad 4e 03 06 3d 32 33 5f 32 } //02 00 
		$a_01_1 = {8b 6a 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 01 e9 8b 41 58 01 e8 8b 71 3c 01 ee 03 69 0c 53 6a 01 6a 02 ff d0 } //01 00 
		$a_01_2 = {68 02 00 11 5c 89 e1 53 b7 0c } //01 00 
		$a_01_3 = {53 51 57 51 6a 10 51 57 56 ff e5 } //01 00 
		$a_01_4 = {68 74 74 70 3a } //00 00  http:
		$a_00_5 = {5d 04 00 } //00 99 
	condition:
		any of ($a_*)
 
}