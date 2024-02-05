
rule Ransom_Win32_Teerac_J{
	meta:
		description = "Ransom:Win32/Teerac.J,SIGNATURE_TYPE_PEHSTR_EXT,fffffffe 01 fffffffe 01 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 6a 50 6a 03 56 6a 01 68 00 00 00 80 68 90 01 04 ff 90 00 } //0a 00 
		$a_03_1 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 68 90 01 04 ff 90 00 } //64 00 
		$a_03_2 = {6a 04 68 00 10 00 00 6a 04 90 01 01 ff 90 00 } //64 00 
		$a_03_3 = {07 00 01 00 ff 90 09 02 00 c7 90 00 } //64 00 
		$a_01_4 = {8b 43 50 8b 4b 34 6a 40 68 00 30 00 00 } //64 00 
		$a_03_5 = {b0 00 00 00 ff 90 09 02 00 89 90 00 } //64 00 
		$a_03_6 = {68 10 27 00 00 ff 90 02 02 ff 75 90 01 01 ff 90 02 02 6a 00 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}