
rule Virus_Win32_Nabucur_gen_A{
	meta:
		description = "Virus:Win32/Nabucur.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {60 0f 31 33 c2 61 } //01 00 
		$a_01_1 = {0f c8 93 0f cb 87 de 0f ce 87 f7 0f cf 41 3b ca 75 ee } //01 00 
		$a_01_2 = {33 d2 bb 05 00 00 00 f7 f3 8b 75 08 83 c2 03 8b ca e2 fe } //01 00 
		$a_03_3 = {31 06 83 c6 04 83 c1 04 81 f9 90 01 02 00 00 7c f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}