
rule Virus_Win32_Sirefef_gen_A{
	meta:
		description = "Virus:Win32/Sirefef.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 53 63 55 6e } //01 00  hScUn
		$a_03_1 = {8b 75 0c 8b 46 04 57 6a 5c 50 ff 15 90 01 04 8b 90 01 05 90 02 04 85 c0 75 0a 90 00 } //01 00 
		$a_01_2 = {56 8a 0a 6b c0 21 0f be f1 33 c6 42 84 c9 75 f1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Virus_Win32_Sirefef_gen_A_2{
	meta:
		description = "Virus:Win32/Sirefef.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 53 63 55 6e } //01 00  hScUn
		$a_03_1 = {8b 75 0c 8b 46 04 57 6a 5c 50 ff 15 90 01 04 8b 90 01 05 90 02 04 85 c0 75 0a 90 00 } //01 00 
		$a_01_2 = {56 8a 0a 6b c0 21 0f be f1 33 c6 42 84 c9 75 f1 } //00 00 
	condition:
		any of ($a_*)
 
}