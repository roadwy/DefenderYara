
rule Trojan_Win32_Swisyn_J{
	meta:
		description = "Trojan:Win32/Swisyn.J,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 29 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {33 d2 f2 ae 89 54 24 19 } //0a 00 
		$a_01_1 = {c6 44 24 24 00 c6 44 24 10 00 f3 a5 8b c8 } //0a 00 
		$a_01_2 = {33 c0 8b fe 68 04 01 00 00 f3 ab 56 ff 15 } //0a 00 
		$a_01_3 = {85 c0 74 27 6a 14 ff 15 } //01 00 
		$a_01_4 = {41 75 5f 6a 69 68 61 6f 00 } //01 00 
		$a_01_5 = {41 75 5f 69 6e 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}